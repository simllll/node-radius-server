// https://tools.ietf.org/html/rfc5281 TTLS v0
// https://tools.ietf.org/html/draft-funk-eap-ttls-v1-00 TTLS v1 (not implemented)
/* eslint-disable no-bitwise */
import { IPacketHandlerResult, PacketResponseCode } from '../../../../interfaces/PacketHandler';
import { IEAPMethod } from '../../../../interfaces/EAPMethod';
import { IAuthentication } from '../../../../interfaces/Authentication';
import { buildEAPResponse, decodeEAPHeader } from '../EAPHelper';
import { ILogger } from '../../../../interfaces/Logger';

export class EAPGTC implements IEAPMethod {
	getEAPType(): number {
		return 6;
	}

	extractValue(msg: Buffer) {
		let tillBinary0 = msg.findIndex((v) => v === 0) || msg.length;
		if (tillBinary0 < 0) {
			tillBinary0 = msg.length - 1;
		}
		return msg.slice(0, tillBinary0 + 1); // use token til binary 0.
	}

	identify(identifier: number, _stateID: string): IPacketHandlerResult {
		return buildEAPResponse(identifier, 6, Buffer.from('Password: '));
	}

	constructor(private authentication: IAuthentication, private logger: ILogger) {}

	async handleMessage(
		_identifier: number,
		_stateID: string,
		msg: Buffer,
		_,
		identity?: string
	): Promise<IPacketHandlerResult> {
		const username = identity; // this.loginData.get(stateID) as Buffer | undefined;

		try {
			const { data } = decodeEAPHeader(msg);

			const token = this.extractValue(data);

			if (!username) {
				throw new Error('no username');
			}

			this.logger.debug('username', username, username.toString());
			this.logger.debug('token', token, token.toString());

			const success = await this.authentication.authenticate(username.toString(), token.toString());

			return {
				code: success ? PacketResponseCode.AccessAccept : PacketResponseCode.AccessReject,
				attributes: (success && [['User-Name', username]]) || undefined,
			};
		} catch (err) {
			this.logger.error('decoding of EAP-GTC package failed', msg, err);
			return {
				code: PacketResponseCode.AccessReject,
			};
		}
	}
}
