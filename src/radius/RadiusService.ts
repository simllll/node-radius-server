import * as radius from 'radius';
import { IAuthentication } from '../types/Authentication';
import { EAPPacketHandler } from './handler/EAPPacketHandler';
import { DefaultPacketHandler } from './handler/DefaultPacketHandler';
import { IPacketHandler, IPacketHandlerResult, PacketResponseCode } from '../types/PacketHandler';

import { EAPTTLS } from './handler/eap/eapMethods/EAP-TTLS';
import { EAPMD5 } from './handler/eap/eapMethods/EAP-MD5';
import { EAPGTC } from './handler/eap/eapMethods/EAP-GTC';

export class RadiusService {
	radiusPacketHandlers: IPacketHandler[] = [];

	constructor(private secret: string, private authentication: IAuthentication) {
		this.radiusPacketHandlers.push(
			new EAPPacketHandler([
				new EAPTTLS(authentication),
				new EAPGTC(authentication),
				new EAPMD5(authentication)
			])
		);
		this.radiusPacketHandlers.push(new DefaultPacketHandler(authentication));
	}

	async handleMessage(
		msg: Buffer
	): Promise<{ data: Buffer; expectAcknowledgment?: boolean } | undefined> {
		const packet = radius.decode({ packet: msg, secret: this.secret });

		if (packet.code !== 'Access-Request') {
			console.error('unknown packet type: ', packet.code);
			return undefined;
		}

		let response: IPacketHandlerResult;

		let i = 0;
		if (!this.radiusPacketHandlers[i]) {
			throw new Error('no packet handlers registered');
		}

		// process packet handlers until we get a response from one
		do {
			/* response is of type IPacketHandlerResult */
			response = await this.radiusPacketHandlers[i].handlePacket(packet.attributes, packet);
			i++;
		} while (this.radiusPacketHandlers[i] && (!response || !response.code));

		// still no response, we are done here
		if (!response || !response.code) {
			return undefined;
		}

		// all fine, return radius encoded response
		return {
			data: radius.encode_response({
				packet,
				code: response.code,
				secret: this.secret,
				attributes: response.attributes
			}),
			// if message is accept or reject, we conside this as final message
			// this means we do not expect a reponse from the client again (acknowledgement for package)
			expectAcknowledgment: response.code === PacketResponseCode.AccessChallenge
		};
	}
}
