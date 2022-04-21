import * as tls from 'tls';

import { IPacket, IPacketHandler, IPacketHandlerResult } from '../interfaces/PacketHandler.js';
import { IAuthentication } from '../interfaces/Authentication.js';
import { EAPPacketHandler } from './handler/EAPPacketHandler.js';
import { EAPTTLS } from './handler/eap/eapMethods/EAP-TTLS.js';
import { EAPGTC } from './handler/eap/eapMethods/EAP-GTC.js';
import { EAPMD5 } from './handler/eap/eapMethods/EAP-MD5.js';
import { UserPasswordPacketHandler } from './handler/UserPasswordPacketHandler.js';
import { Logger } from '../logger/Logger.js';

export class PacketHandler implements IPacketHandler {
	private logger = new Logger('PacketHandler');

	packetHandlers: IPacketHandler[] = [];

	constructor(
		authentication: IAuthentication,
		tlsOptions: tls.SecureContextOptions,
		private secret: string,
		private vlan?: number
	) {
		this.packetHandlers.push(
			new EAPPacketHandler([
				new EAPTTLS(authentication, tlsOptions, this, secret, vlan),
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
