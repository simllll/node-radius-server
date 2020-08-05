// https://tools.ietf.org/html/rfc3748#section-4.1

import * as NodeCache from 'node-cache';
import debug from 'debug';
import { makeid } from '../../helpers';
import { IPacket, IPacketHandler, IPacketHandlerResult } from '../../types/PacketHandler';
import { IEAPMethod } from '../../types/EAPMethod';
import { buildEAPResponse, decodeEAPHeader } from './eap/EAPHelper';

const log = debug('radius:eap');

export class EAPPacketHandler implements IPacketHandler {
	private identities = new NodeCache({ useClones: false, stdTTL: 60 }); // queue data maximum for 60 seconds

	// 	private eapConnectionStates: { [key: string]: { validMethods: IEAPMethod[] } } = {};
	private eapConnectionStates = new NodeCache({ useClones: false, stdTTL: 3600 }); // max for one hour

	constructor(private eapMethods: IEAPMethod[]) {}

	async handlePacket(packet: IPacket, handlingType?: number): Promise<IPacketHandlerResult> {
		if (!packet.attributes['EAP-Message']) {
			// not an EAP message
			return {};
		}

		const stateID = (packet.attributes.State && packet.attributes.State.toString()) || makeid(16);

		if (!this.eapConnectionStates.get(stateID)) {
			this.eapConnectionStates.set(stateID, {
				validMethods: this.eapMethods.filter((eap) => eap.getEAPType() !== handlingType), // on init all registered eap methods are valid, we kick them out in case we get a NAK response
			});
		}

		// EAP MESSAGE
		let msg = packet.attributes['EAP-Message'] as Buffer;

		if (Array.isArray(msg) && !(packet.attributes['EAP-Message'] instanceof Buffer)) {
			// log('multiple EAP Messages received, concat', msg.length);
			const allMsgs = msg as Buffer[];
			msg = Buffer.concat(allMsgs);
			// log('final EAP Message', msg);
		}

		try {
			const { code, type, identifier, data } = decodeEAPHeader(msg);

			const currentState = this.eapConnectionStates.get(stateID) as { validMethods: IEAPMethod[] };

			switch (code) {
				case 1: // for request
				case 2: // for response
					switch (type) {
						case 1: // identifiy
							log('>>>>>>>>>>>> REQUEST FROM CLIENT: IDENTIFY', stateID, data.toString());
							if (data) {
								this.identities.set(stateID, data); // use token til binary 0.);
							} else {
								log('no msg');
							}

							// start identify
							if (currentState.validMethods.length > 0) {
								return currentState.validMethods[0].identify(identifier, stateID, data);
							}

							return buildEAPResponse(identifier, 3); // NAK
						case 2: // notification
							log('>>>>>>>>>>>> REQUEST FROM CLIENT: notification', {});
							console.info('notification');
							break;
						case 4: // md5-challenge
							log('>>>>>>>>>>>> REQUEST FROM CLIENT: md5-challenge', {});

							console.info('md5-challenge');
							break;
						case 254: // expanded type
							console.error('not implemented type', type);
							break;
						case 3: // nak
							// console.log('got NAK', data);
							if (data) {
								// if there is data, each data octect reprsents a eap method the clients supports,
								// kick out all unsupported ones
								const supportedEAPMethods: number[] = [];
								for (const supportedMethod of data) {
									supportedEAPMethods.push(supportedMethod);
								}

								currentState.validMethods = currentState.validMethods.filter((method) => {
									return supportedEAPMethods.includes(method.getEAPType()); // kick it out?
								});
								// save
								this.eapConnectionStates.set(stateID, currentState);

								// new identidy request
								// start identify
								if (currentState.validMethods.length > 0) {
									return currentState.validMethods[0].identify(identifier, stateID, data);
								}
							}
						// continue with responding a NAK and add rest of supported methods
						// eslint-disable-next-line no-fallthrough
						default: {
							const eapMethod = this.eapMethods.find((method) => {
								return type === method.getEAPType();
							});

							if (eapMethod) {
								return eapMethod.handleMessage(
									identifier,
									stateID,
									msg,
									packet,
									this.identities.get(stateID)
								);
							}

							// we do not support this auth type, ask for something we support
							const serverSupportedMethods = currentState.validMethods.map((method) =>
								method.getEAPType()
							);

							console.error('unsupported type', type, `requesting: ${serverSupportedMethods}`);

							return buildEAPResponse(identifier, 3, Buffer.from(serverSupportedMethods));
						}
					}
					break;
				case 3:
					log('Client Auth Success');
					break;
				case 4:
					log('Client Auth FAILURE');
					break;
				default:
			}
			// silently ignore;
			return {};
		} catch (err) {
			console.error(
				'decoding of (generic) EAP package failed',
				msg,
				err,
				this.eapConnectionStates.get(stateID)
			);
			return {};
		}
	}
}
