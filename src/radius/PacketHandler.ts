import { IPacket, IPacketHandler, IPacketHandlerResult } from '../types/PacketHandler';
import { IAuthentication } from '../types/Authentication';
import { EAPPacketHandler } from './handler/EAPPacketHandler';
import { EAPTTLS } from './handler/eap/eapMethods/EAP-TTLS';
import { EAPGTC } from './handler/eap/eapMethods/EAP-GTC';
import { EAPMD5 } from './handler/eap/eapMethods/EAP-MD5';
import { UserPasswordPacketHandler } from './handler/UserPasswordPacketHandler';

export class PacketHandler implements IPacketHandler {
	packetHandlers: IPacketHandler[] = [];

	constructor(authentication: IAuthentication) {
		this.packetHandlers.push(
			new EAPPacketHandler([
				new EAPTTLS(authentication, this),
				new EAPGTC(authentication),
				new EAPMD5(authentication),
			])
		);
		this.packetHandlers.push(new UserPasswordPacketHandler(authentication));
	}

	async handlePacket(packet: IPacket, handlingType?: number) {
		let response: IPacketHandlerResult;

		let i = 0;
		if (!this.packetHandlers[i]) {
			throw new Error('no packet handlers registered');
		}

		// process packet handlers until we get a response from one
		do {
			/* response is of type IPacketHandlerResult */
			response = await this.packetHandlers[i].handlePacket(packet, handlingType);
			i++;
		} while (this.packetHandlers[i] && (!response || !response.code));

		return response;
	}
}
