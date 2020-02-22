import { IAuthentication } from '../../types/Authentication';
import {
	IPacketHandler,
	IPacketHandlerResult,
	PacketResponseCode
} from '../../types/PacketHandler';

export class DefaultPacketHandler implements IPacketHandler {
	constructor(private authentication: IAuthentication) {}

	async handlePacket(attributes: { [key: string]: Buffer }): Promise<IPacketHandlerResult> {
		const username = attributes['User-Name'];
		const password = attributes['User-Password'];

		if (!username || !password) {
			// params missing, this handler cannot continue...
			return {};
		}

		const authenticated = await this.authentication.authenticate(
			username.toString(),
			password.toString()
		);
		if (authenticated) {
			// success
			return {
				code: PacketResponseCode.AccessAccept
			};
		}

		// Failed
		return {
			code: PacketResponseCode.AccessReject
		};
	}
}
