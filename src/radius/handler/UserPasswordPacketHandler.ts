import { IAuthentication } from '../../interfaces/Authentication.js';
import {
	IPacket,
	IPacketHandler,
	IPacketHandlerResult,
	PacketResponseCode,
} from '../../interfaces/PacketHandler.js';
import { Logger } from '../../logger/Logger.js';

export class UserPasswordPacketHandler implements IPacketHandler {
	private logger = new Logger('UserPasswordPacketHandler');

	constructor(private authentication: IAuthentication) {}

	async handlePacket(packet: IPacket): Promise<IPacketHandlerResult> {
		const username = packet.attributes['User-Name'];
		let password = packet.attributes['User-Password'];

		if (Buffer.isBuffer(password) && password.indexOf(0x00) > 0) {
			// check if there is a 0x00 in it, and trim it from there
			password = password.slice(0, password.indexOf(0x00));
		}

		if (!username || !password) {
			// params missing, this handler cannot continue...
			return {};
		}

		this.logger.debug('username', username, username.toString());
		this.logger.debug('token', password, password.toString());

		const authenticated = await this.authentication.authenticate(
			username.toString(),
			password.toString()
		);
		if (authenticated) {
			// success
			return {
				code: PacketResponseCode.AccessAccept,
				attributes: [['User-Name', username]],
			};
		}

		// Failed
		return {
			code: PacketResponseCode.AccessReject,
		};
	}
}
