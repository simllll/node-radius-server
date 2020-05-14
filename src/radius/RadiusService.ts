import * as radius from 'radius';
import { IAuthentication } from '../types/Authentication';
import { IPacketHandlerResult, PacketResponseCode } from '../types/PacketHandler';

import { PacketHandler } from './PacketHandler';

export class RadiusService {
	private packetHandler: PacketHandler;

	constructor(private secret: string, authentication: IAuthentication) {
		this.packetHandler = new PacketHandler(authentication);
	}

	async handleMessage(
		msg: Buffer
	): Promise<{ data: Buffer; expectAcknowledgment?: boolean } | undefined> {
		const packet = radius.decode({ packet: msg, secret: this.secret });

		if (packet.code !== 'Access-Request') {
			console.error('unknown packet type: ', packet.code);
			return undefined;
		}

		const response: IPacketHandlerResult = await this.packetHandler.handlePacket(packet);

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
				attributes: response.attributes,
			}),
			// if message is accept or reject, we conside this as final message
			// this means we do not expect a reponse from the client again (acknowledgement for package)
			expectAcknowledgment: response.code === PacketResponseCode.AccessChallenge,
		};
	}
}
