/* eslint-disable no-bitwise */
import * as events from 'events';
import * as tls from 'tls';
import { encodeTunnelPW, openTLSSockets, startTLSServer } from '../tls/crypt';
import { AdditionalAuthHandler, ResponseAuthHandler } from '../types/Handler';
import { PAPChallenge } from './challenges/pap';
import { IEAPType } from '../types/EAPType';

interface IEAPResponseHandlers {
	response: (respData?: Buffer, msgType?: number) => void;
	checkAuth: ResponseAuthHandler;
}

export class EAPTTLS implements IEAPType {
	papChallenge: PAPChallenge;

	constructor(private sendEAPResponse) {
		this.papChallenge = new PAPChallenge();
	}

	decode(msg: Buffer) {
		const flags = msg.slice(5, 6).readUInt8(0); // .toString('hex');

		// if (flags)
		// @todo check if "L" flag is set in flags
		const decodedFlags = {
			lengthIncluded: flags & 0b010000000,
			moreFragments: flags & 0b001000000,
			start: flags & 0b000100000,
			reserved: flags & 0b000011000,
			version: flags & 0b010000111
		};
		let msglength;
		if (decodedFlags.lengthIncluded) {
			msglength = msg.slice(6, 10).readInt32BE(0); // .readDoubleLE(0); // .toString('hex');
		}
		const data = msg.slice(decodedFlags.lengthIncluded ? 10 : 6, msg.length);

		return {
			decodedFlags,
			msglength,
			data
		};
	}

	handleMessage(msg: Buffer, state: string, handlers, identifier: number) {
		const { decodedFlags, msglength, data } = this.decode(msg);

		// check if no data package is there and we have something in the queue, if so.. empty the queue first
		if (!data || data.length === 0) {
			// @todo: queue processing
			console.warn(
				`>>>>>>>>>>>> REQUEST FROM CLIENT: EAP TTLS, ACK / NACK (no data, just a confirmation, ID: ${identifier})`
			);
			return;
		}

		console.log('>>>>>>>>>>>> REQUEST FROM CLIENT: EAP TTLS', {
			// flags: `00000000${flags.toString(2)}`.substr(-8),
			decodedFlags,
			identifier,
			/*
                      0   1   2   3   4   5   6   7
                    +---+---+---+---+---+---+---+---+
                    | L | M | S | R | R |     V     |
                    +---+---+---+---+---+---+---+---+

                    L = Length included
                    M = More fragments
                    S = Start
                    R = Reserved
                    V = Version (000 for EAP-TTLSv0)
                    */

			msglength,
			data,
			dataStr: data.toString()
		});

		let currentConnection = openTLSSockets.get(state) as
			| { events: events.EventEmitter; tls: tls.TLSSocket; currentHandlers: IEAPResponseHandlers }
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
							currentConnection!.currentHandlers.response(undefined, 3);

							/*
							this.sendEAPResponse(
								currentConnection!.currentHandlers.response,
								identifier,
								undefined,
								3
							); */
							currentConnection!.events.emit('end');
							throw new Error(`pwd not found`);
						}
						break;
					default:
						console.log('data', incomingData);
						console.log('data str', incomingData.toString());

						// currentConnection!.events.emit('end');

						console.log('UNSUPPORTED AUTH TYPE, requesting PAP');
						// throw new Error(`unsupported auth type${type}`);
						currentConnection!.currentHandlers.response(Buffer.from([1]), 3);

					/*
						this.sendEAPResponse(
							currentConnection!.currentHandlers.response,
							identifier,
							Buffer.from([1]),
							3
						); */
				}
			});

			currentConnection.events.on('response', (responseData: Buffer) => {
				// console.log('sending encrypted data back to client', responseData);

				// send back...
				currentConnection!.currentHandlers.response(responseData);
				// this.sendEAPResponse(currentConnection!.currentHandlers.response, identifier, responseData);
				// this.sendMessage(TYPE.PRELOGIN, data, false);
			});

			currentConnection.events.on('end', () => {
				// cleanup socket
				console.log('ENDING SOCKET');
				openTLSSockets.del(state);
			});
		} /* else {
			console.log('using existing socket');
		} */

		// update handlers
		currentConnection.currentHandlers = {
			response: (respData?: Buffer, msgType?: number) =>
				this.sendEAPResponse(handlers.response, identifier, respData, msgType),
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

					// console.log('keyingMaterial', keyingMaterial);

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
