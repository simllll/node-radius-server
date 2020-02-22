// https://tools.ietf.org/html/rfc3748#section-4.1

import * as NodeCache from 'node-cache';
import { RadiusPacket } from 'radius';
import { EAPTTLS } from './eapMethods/EAPTTLS';
import { makeid } from '../../helpers';
import {
	IPacketHandler,
	IPacketHandlerResult,
	PacketResponseCode
} from '../../types/PacketHandler';
import { IAuthentication } from '../../types/Authentication';
import { IEAPMethod } from '../../types/EAPMethod';

export class EAPPacketHandler implements IPacketHandler {
	private eapMethods: IEAPMethod[] = [];

	// 	private eapConnectionStates: { [key: string]: { validMethods: IEAPMethod[] } } = {};
	private eapConnectionStates = new NodeCache({ useClones: false, stdTTL: 3600 }); // max for one hour

	constructor(authentication: IAuthentication) {
		this.eapMethods.push(new EAPTTLS(authentication));
	}

	/**
	 *
	 * @param data
	 * @param msgType 1 = identity, 21 = EAP-TTLS, 2 = notification, 4 = md5-challenge, 3 = NAK
	 */
	private async buildEAPResponse(
		identifier: number,
		msgType: number,
		data?: Buffer
	): Promise<IPacketHandlerResult> {
		/** build a package according to this:
			0                   1                   2                   3
			0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 |     Code      |  Identifier   |            Length             |
		 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 |     Type      |  Type-Data ...
		 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
		 */
		const buffer = Buffer.from([
			1, // request
			identifier,
			0, // length (1/2)
			0, //  length (2/2)
			msgType // 1 = identity, 21 = EAP-TTLS, 2 = notificaiton, 4 = md5-challenge, 3 = NAK
		]);

		const resBuffer = data ? Buffer.concat([buffer, data]) : buffer;
		// set EAP length header
		resBuffer.writeUInt16BE(resBuffer.byteLength, 2);

		return {
			code: PacketResponseCode.AccessChallenge,
			attributes: [['EAP-Message', buffer]]
		};
	}

	private decodeEAPHeader(msg: Buffer) {
		/**
		 * parse msg according to this:
		  0                   1                   2                   3
			0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 |     Code      |  Identifier   |            Length             |
		 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 |     Type      |  Type-Data ...
		 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
		 */

		/*
		code:
        1       Request
        2       Response
        3       Success
        4       Failure
         */
		const code = msg.slice(0, 1).readUInt8(0);
		/* identifier is a number */
		const identifier = msg.slice(1, 2).readUInt8(0);
		const length = msg.slice(2, 4).readInt16BE(0);
		/* EAP type */
		const type = msg.slice(4, 5).readUInt8(0);
		const data = msg.slice(5);

		return {
			code,
			identifier,
			length,
			type,
			data
		};
	}

	async handlePacket(
		attributes: { [key: string]: Buffer },
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
		const msg = attributes['EAP-Message'];

		const { code, type, identifier, data } = this.decodeEAPHeader(msg);

		const currentState = this.eapConnectionStates.get(stateID) as { validMethods: IEAPMethod[] };

		switch (code) {
			case 1: // for request
			case 2: // for response
				switch (type) {
					case 1: // identifiy
						console.log('>>>>>>>>>>>> REQUEST FROM CLIENT: IDENTIFY', {});
						// start identify
						if (currentState.validMethods.length > 0) {
							return currentState.validMethods[0].identify(identifier, stateID);
						}

						return this.buildEAPResponse(identifier, 3);
					case 2: // notification
						console.log('>>>>>>>>>>>> REQUEST FROM CLIENT: notification', {});
						console.info('notification');
						break;
					case 4: // md5-challenge
						console.log('>>>>>>>>>>>> REQUEST FROM CLIENT: md5-challenge', {});

						console.info('md5-challenge');
						break;
					case 254: // expanded type
						console.error('not implemented type', type);
						break;
					case 3: // nak
						if (data) {
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

						return this.buildEAPResponse(identifier, 3, Buffer.from(serverSupportedMethods));
					}
				}
				break;
			case 3:
				console.log('Client Auth Success');
				break;
			case 4:
				console.log('Client Auth FAILURE');
				break;
			default:
		}
		// silently ignore;
		return {};
	}
}
