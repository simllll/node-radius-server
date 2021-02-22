// https://tools.ietf.org/html/rfc5281 TTLS v0
// https://tools.ietf.org/html/draft-funk-eap-ttls-v1-00 TTLS v1 (not implemented)
/* eslint-disable no-bitwise */
import debug from 'debug';
import { IPacket, IPacketHandlerResult, PacketResponseCode } from '../../../../types/PacketHandler';
import { IEAPMethod, EAPMessageType } from '../../../../types/EAPMethod';
import { IAuthentication } from '../../../../types/Authentication';
import { buildEAPResponse, decodeEAPHeader, authResponse } from '../EAPHelper';

const log = debug('radius:eap:gtc');

export class EAPGTC implements IEAPMethod {
	getEAPType(): number {
		return EAPMessageType.GTC;
	}

	extractValue(msg: Buffer): Buffer {
		let tillBinary0 = msg.findIndex((v) => v === 0) || msg.length;
		if (tillBinary0 < 0) {
			tillBinary0 = msg.length - 1;
		}
		return msg.slice(0, tillBinary0 + 1); // use token til binary 0.
	}

	identify(identifier: number, _stateID: string): IPacketHandlerResult {
		return buildEAPResponse(identifier, 6, Buffer.from('Password: '));
	}

	constructor(private authentication: IAuthentication) {}

	async handleMessage(
		identifier: number,
		_stateID: string,
		msg: Buffer,
		packet: IPacket
	): Promise<IPacketHandlerResult> {
		try {
			const username = packet.attributes['User-Name'];
			const { data } = decodeEAPHeader(msg, true);

			const token = this.extractValue(data);

			if (!username) {
				throw new Error('no username');
			}

			if (!token) {
				throw new Error('no challenge');
			}

			log('username', username, username.toString());
			log('token', token, token.toString());

			const success = await this.authentication.authenticate(username.toString(), token.toString());

			return authResponse(identifier, success, packet);
		} catch (err) {
			console.error('decoding of EAP-GTC package failed', msg, err);
			return {
				code: PacketResponseCode.AccessReject,
			};
		}
	}
}
