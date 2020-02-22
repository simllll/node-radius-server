import * as radius from 'radius';
import { IAuthentication } from '../types/Authentication';
import { EAPPacketHandler } from './handler/EAPPacketHandler';
import { DefaultPacketHandler } from './handler/DefaultPacketHandler';
import { IPacketHandler, IPacketHandlerResult, PacketResponseCode } from '../types/PacketHandler';

export class RadiusService {
	radiusPacketHandlers: IPacketHandler[] = [];

	constructor(private secret: string, private authentication: IAuthentication) {
		this.radiusPacketHandlers.push(new EAPPacketHandler(authentication));
		this.radiusPacketHandlers.push(new DefaultPacketHandler(authentication));
	}

	async handleMessage(
		msg: Buffer
	): Promise<{ data: Buffer; expectAcknowledgment?: boolean } | undefined> {
		const packet = radius.decode({ packet: msg, secret: this.secret });

		if (packet.code !== 'Access-Request') {
			console.log('unknown packet type: ', packet.code);
			return undefined;
		}
		// console.log('packet.attributes', packet.attributes);

		// console.log('rinfo', rinfo);
		/*
		const checkAuth = async (
			username: string,
			password: string,
			additionalAuthHandler?: AdditionalAuthHandler
		) => {
			console.log(`Access-Request for ${username}`);
			let success = false;
			try {
				await this.authentication.authenticate(username, password);
				success = true;
			} catch (err) {
				console.error(err);
			}

			const attributes: any[] = [];

			if (additionalAuthHandler) {
				await additionalAuthHandler(success, { packet, attributes, secret: this.secret });
			}

			const response = radius.encode_response({
				packet,
				code: success ? 'Access-Accept' : 'Access-Reject',
				secret: this.secret,
				attributes
			});
			console.log(`Sending ${success ? 'accept' : 'reject'} for user ${username}`);

			this.server.sendToClient(response, rinfo.port, rinfo.address, function(err, _bytes) {
				if (err) {
					console.log('Error sending response to ', rinfo);
				}
			});
		}; */

		let response: IPacketHandlerResult;

		let i = 0;
		if (!this.radiusPacketHandlers[i]) {
			throw new Error('no packet handlers registered');
		}

		// process packet handlers until we get a response
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
