// https://tools.ietf.org/html/rfc5281 TTLS v0
// https://tools.ietf.org/html/draft-funk-eap-ttls-v1-00 TTLS v1 (not implemented)
/* eslint-disable no-bitwise */
import debug from 'debug';
import { IPacketHandlerResult, PacketResponseCode } from '../../../../types/PacketHandler';
import { IEAPMethod } from '../../../../types/EAPMethod';
import { IAuthentication } from '../../../../types/Authentication';
import { buildEAPResponse, decodeEAPHeader } from '../EAPHelper';

const log = debug('radius:eap:gtc');

export class EAPGTC implements IEAPMethod {
	getEAPType(): number {
		return 6;
	}

	extractValue(msg: Buffer) {
		let tillBinary0 = msg.findIndex(v => v === 0) || msg.length;
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
		_identifier: number,
		_stateID: string,
		msg: Buffer,
		_,
		identity?: string
	): Promise<IPacketHandlerResult> {
		const username = identity; // this.loginData.get(stateID) as Buffer | undefined;

		const { data } = decodeEAPHeader(msg);

		const token = this.extractValue(data);

		if (!username) {
			throw new Error('no username');
		}

		log('username', username, username.toString());
		log('token', token, token.toString());

		const success = await this.authentication.authenticate(username.toString(), token.toString());

		return {
			code: success ? PacketResponseCode.AccessAccept : PacketResponseCode.AccessReject,
			attributes: (success && [['User-Name', username]]) || undefined
		};
	}
}
