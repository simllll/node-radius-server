import * as events from 'events';
import { openTLSSockets, startTLSServer } from '../tls/crypt';
import { IResponseHandlers } from '../types/Handler';
import { PAPChallenge } from './challenges/pap';
import { IEAPType } from '../types/EAPType';

export class EAPTTLS implements IEAPType {
	papChallenge: PAPChallenge;

	constructor(private sendEAPResponse) {
		this.papChallenge = new PAPChallenge();
	}

	handleMessage(msg: Buffer, state: string, handlers, identifier: number) {
		const flags = msg.slice(5, 6); // .toString('hex');

		// if (flags)
		// @todo check if "L" flag is set in flags
		const msglength = msg.slice(6, 10).readInt32BE(0); // .toString('hex');
		const data = msg.slice(6, msg.length); // 10); //.toString('hex');

		// check if no data package is there and we have something in the queue, if so.. empty the queue first
		if (!data) {
			// @todo: queue processing
			console.warn('no data, just a confirmation!');
			return;
		}

		console.log('incoming EAP TTLS', {
			flags /*
                      0   1   2   3   4   5   6   7
                    +---+---+---+---+---+---+---+---+
                    | L | M | S | R | R |     V     |
                    +---+---+---+---+---+---+---+---+

                    L = Length included
                    M = More fragments
                    S = Start
                    R = Reserved
                    V = Version (000 for EAP-TTLSv0)
                    */,
			msglength,
			data,
			dataStr: data.toString()
		});

		let sslLayer = openTLSSockets.get(state) as
			| { socket: events.EventEmitter; currentHandlers: IResponseHandlers }
			| undefined;
		if (!sslLayer) {
			const newSocket = startTLSServer();
			sslLayer = { socket: newSocket, currentHandlers: handlers };
			openTLSSockets.set(state, sslLayer);

			// register event listeners
			newSocket.on('incoming', (incomingData: Buffer) => {
				const type = incomingData.slice(3, 4).readUInt8(0);
				// const code = data.slice(4, 5).readUInt8(0);

				switch (type) {
					case 1: // PAP / CHAP
						try {
							const { username, password } = this.papChallenge.decode(incomingData);
							sslLayer!.currentHandlers.checkAuth(username, password, identifier);
						} catch (err) {
							// pwd not found..
							console.error('pwd not found', err);
							// NAK
							this.sendEAPResponse(sslLayer!.currentHandlers.response, identifier, undefined, 3);
							newSocket.emit('end');
							throw new Error(`pwd not found`);
						}
						break;
					default:
						console.log('data', incomingData);
						console.log('data str', incomingData.toString());

						newSocket.emit('end');
						throw new Error(`unsupported auth type${type}`);
				}
			});

			newSocket.on('response', (responseData: Buffer) => {
				console.log('sending encrypted data back to client', responseData);

				// send back...
				this.sendEAPResponse(sslLayer!.currentHandlers.response, identifier, responseData);
				// this.sendMessage(TYPE.PRELOGIN, data, false);
			});

			newSocket.on('end', () => {
				// cleanup socket
				console.log('ENDING SOCKET');
				openTLSSockets.del(state);
			});
		} else {
			console.log('using existing socket');
		}

		// update handlers
		sslLayer.currentHandlers = {
			...handlers,
			checkAuth: (username: string, password: string) =>
				handlers.checkAuth(username, password, identifier)
		};

		// emit data to tls server
		sslLayer.socket.emit('send', data);
	}
}
