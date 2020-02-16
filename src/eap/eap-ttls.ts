import * as events from 'events';
import * as tls from 'tls';
import { encodeTunnelPW, openTLSSockets, startTLSServer } from '../tls/crypt';
import { AdditionalAuthHandler, IResponseHandlers } from '../types/Handler';
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

		let currentConnection = openTLSSockets.get(state) as
			| { events: events.EventEmitter; tls: tls.TLSSocket; currentHandlers: IResponseHandlers }
			| undefined;
		if (!currentConnection) {
			const connection = startTLSServer();
			currentConnection = {
				events: connection.events,
				tls: connection.tls,
				currentHandlers: handlers
			};
			openTLSSockets.set(state, currentConnection);

			// register event listeners
			currentConnection.events.on('incoming', (incomingData: Buffer) => {
				const type = incomingData.slice(3, 4).readUInt8(0);
				// const code = data.slice(4, 5).readUInt8(0);

				switch (type) {
					case 1: // PAP / CHAP
						try {
							const { username, password } = this.papChallenge.decode(incomingData);
							currentConnection!.currentHandlers.checkAuth(username, password);
						} catch (err) {
							// pwd not found..
							console.error('pwd not found', err);
							// NAK
							this.sendEAPResponse(
								currentConnection!.currentHandlers.response,
								identifier,
								undefined,
								3
							);
							currentConnection!.events.emit('end');
							throw new Error(`pwd not found`);
						}
						break;
					default:
						console.log('data', incomingData);
						console.log('data str', incomingData.toString());

						currentConnection!.events.emit('end');
						throw new Error(`unsupported auth type${type}`);
				}
			});

			currentConnection.events.on('response', (responseData: Buffer) => {
				console.log('sending encrypted data back to client', responseData);

				// send back...
				this.sendEAPResponse(currentConnection!.currentHandlers.response, identifier, responseData);
				// this.sendMessage(TYPE.PRELOGIN, data, false);
			});

			currentConnection.events.on('end', () => {
				// cleanup socket
				console.log('ENDING SOCKET');
				openTLSSockets.del(state);
			});
		} else {
			console.log('using existing socket');
		}

		// update handlers
		currentConnection.currentHandlers = {
			...handlers,
			checkAuth: (username: string, password: string) => {
				const additionalAuthHandler: AdditionalAuthHandler = (success, params) => {
					const buffer = Buffer.from([
						success ? 3 : 4, // 3.. success, 4... failure
						identifier,
						0, // length (1/2)
						4 //  length (2/2)
					]);

					params.attributes.push(['EAP-Message', buffer]);

					if (params.packet.attributes && params.packet.attributes['User-Name']) {
						// reappend username to response
						params.attributes.push(['User-Name', params.packet.attributes['User-Name']]);
					}

					/*
                if (sess->eap_if->eapKeyDataLen > 64) {
                              len = 32;
                      } else {
                              len = sess->eap_if->eapKeyDataLen / 2;
                      }
                 */
					const keyingMaterial = (currentConnection?.tls as any).exportKeyingMaterial(
						128,
						'ttls keying material'
					);

					console.log('keyingMaterial', keyingMaterial);

					// eapKeyData + len
					params.attributes.push([
						'Vendor-Specific',
						311,
						[
							[
								16,
								encodeTunnelPW(
									keyingMaterial.slice(64),
									(params.packet as any).authenticator,
									// params.packet.attributes['Message-Authenticator'],
									params.secret
								)
							]
						]
					]); //  MS-MPPE-Send-Key

					// eapKeyData
					params.attributes.push([
						'Vendor-Specific',
						311,
						[
							[
								17,
								encodeTunnelPW(
									keyingMaterial.slice(0, 64),
									(params.packet as any).authenticator,
									// params.packet.attributes['Message-Authenticator'],
									params.secret
								)
							]
						]
					]); // MS-MPPE-Recv-Key
				};

				return handlers.checkAuth(username, password, additionalAuthHandler);
			}
		};

		// emit data to tls server
		currentConnection.events.emit('send', data);
	}
}
