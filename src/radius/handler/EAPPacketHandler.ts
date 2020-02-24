// https://tools.ietf.org/html/rfc3748#section-4.1

import * as NodeCache from 'node-cache';
import { RadiusPacket } from 'radius';
import debug from 'debug';
import { makeid } from '../../helpers';
import { IPacketHandler, IPacketHandlerResult } from '../../types/PacketHandler';
import { IEAPMethod } from '../../types/EAPMethod';
import { buildEAPResponse, decodeEAPHeader } from './eap/EAPHelper';

const log = debug('radius:eap');

export class EAPPacketHandler implements IPacketHandler {
	// 	private eapConnectionStates: { [key: string]: { validMethods: IEAPMethod[] } } = {};
	private eapConnectionStates = new NodeCache({ useClones: false, stdTTL: 3600 }); // max for one hour

	constructor(private eapMethods: IEAPMethod[]) {}

	async handlePacket(
		attributes: { [key: string]: Buffer | string },
		orgRadiusPacket: RadiusPacket
	): Promise<IPacketHandlerResult> {
		if (!attributes['EAP-Message']) {
			// not an EAP message
			return {};
		}

		const stateID = (attributes.State && attributes.State.toString()) || makeid(16);

		if (!this.eapConnectionStates.get(stateID)) {
			this.eapConnectionStates.set(stateID, {
				validMethods: this.eapMethods // on init all registered eap methods are valid, we kick them out in case we get a NAK response
			});
		}

		// EAP MESSAGE
		const msg = attributes['EAP-Message'] as Buffer;

		const { code, type, identifier, data } = decodeEAPHeader(msg);

		const currentState = this.eapConnectionStates.get(stateID) as { validMethods: IEAPMethod[] };

		switch (code) {
			case 1: // for request
			case 2: // for response
				switch (type) {
					case 1: // identifiy
						log('>>>>>>>>>>>> REQUEST FROM CLIENT: IDENTIFY', {});
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
						if (data) {
							// if there is data, each data octect reprsents a eap method the clients supports,
							// kick out all unsupported ones
							const supportedEAPMethods: number[] = [];
							for (const supportedMethod of data) {
								supportedEAPMethods.push(supportedMethod);
							}

							this.eapConnectionStates.set(stateID, {
								...currentState,
								validMethods: currentState.validMethods.filter(method => {
									return supportedEAPMethods.includes(method.getEAPType()); // kick it out?
								})
							});
						}
					// continue with responding a NAK and add rest of supported methods
					// eslint-disable-next-line no-fallthrough
					default: {
						const eapMethod = currentState.validMethods.find(method => {
							return type === method.getEAPType();
						});

						if (eapMethod) {
							return eapMethod.handleMessage(identifier, stateID, msg, orgRadiusPacket);
						}

						// we do not support this auth type, ask for something we support
						const serverSupportedMethods = currentState.validMethods.map(
							method => method.getEAPType
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
	}
}
