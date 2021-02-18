import debug from 'debug';
import { IAuthentication } from '../../types/Authentication';
import {
	IPacket,
	IPacketHandler,
	IPacketHandlerResult,
	PacketResponseCode,
} from '../../types/PacketHandler';

const log = debug('radius:user-pwd');

export class UserPasswordPacketHandler implements IPacketHandler {
	constructor(private authentication: IAuthentication) {}

	async handlePacket(packet: IPacket): Promise<IPacketHandlerResult> {
		const username = packet.attributes['User-Name'];
		let password = packet.attributes['User-Password'];
		if (Buffer.isBuffer(password)) {
			password = password.slice(0, password.indexOf('\0'));
		}

		if (!username || !password) {
			// params missing, this handler cannot continue...
			return {};
		}

		log('username', username, username.toString());
		log('token', password, password.toString());

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
		console.error('decoding of UserPassword package failed');
		return {
			code: PacketResponseCode.AccessReject,
		};
	}
}
