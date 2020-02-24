// https://tools.ietf.org/html/rfc5281 TTLS v0
// https://tools.ietf.org/html/draft-funk-eap-ttls-v1-00 TTLS v1 (not implemented)
/* eslint-disable no-bitwise */
import * as NodeCache from 'node-cache';
import debug from 'debug';
import { IPacketHandlerResult, PacketResponseCode } from '../../../../types/PacketHandler';
import { IEAPMethod } from '../../../../types/EAPMethod';
import { IAuthentication } from '../../../../types/Authentication';
import { buildEAPResponse, decodeEAPHeader } from '../EAPHelper';

const log = debug('radius:eap:gtc');

export class EAPGTC implements IEAPMethod {
	private loginData = new NodeCache({ useClones: false, stdTTL: 60 }); // queue data maximum for 60 seconds

	getEAPType(): number {
		return 6;
	}

	identify(identifier: number, stateID: string, msg?: Buffer): IPacketHandlerResult {
		if (msg) {
			const parsedMsg = msg.slice(
				0,
				msg.findIndex(v => v === 0)
			);
			log('identify', parsedMsg, parsedMsg.toString());
			this.loginData.set(stateID, parsedMsg); // use token til binary 0.);
		} else {
			log('no msg');
		}

		return buildEAPResponse(identifier, 6, Buffer.from('Password: '));
	}

	constructor(private authentication: IAuthentication) {}

	async handleMessage(
		_identifier: number,
		stateID: string,
		msg: Buffer
	): Promise<IPacketHandlerResult> {
		const username = this.loginData.get(stateID) as Buffer | undefined;

		const { data } = decodeEAPHeader(msg);

		let tillBinary0 = data.findIndex(v => v === 0) || data.length;
		if (tillBinary0 < 0) {
			tillBinary0 = data.length - 1;
		}
		const token = data.slice(0, tillBinary0 + 1); // use token til binary 0.

		if (!username) {
			throw new Error('no username');
		}

		log('username', username, username.toString());
		log('token', token, token.toString());

		const success = await this.authentication.authenticate(username.toString(), token.toString());

		return {
			code: success ? PacketResponseCode.AccessAccept : PacketResponseCode.AccessReject
		};
	}
}
