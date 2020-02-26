// https://tools.ietf.org/html/rfc5281 TTLS v0
// https://tools.ietf.org/html/draft-funk-eap-ttls-v1-00 TTLS v1 (not implemented)
/* eslint-disable no-bitwise */
import { RadiusPacket } from 'radius';
import debug from 'debug';
import { IPacketHandlerResult } from '../../../../types/PacketHandler';
import { IEAPMethod } from '../../../../types/EAPMethod';
import { IAuthentication } from '../../../../types/Authentication';

export class EAPMD5 implements IEAPMethod {
	getEAPType(): number {
		return 4;
	}

	identify(_identifier: number, _stateID: string): IPacketHandlerResult {
		// NOT IMPLEMENTED
		return {};
	}

	constructor(private authentication: IAuthentication) {}

	async handleMessage(
		_identifier: number,
		_stateID: string,
		_msg: Buffer,
		_orgRadiusPacket: RadiusPacket
	): Promise<IPacketHandlerResult> {
		// not implemented

		debug('eap md5 not implemented...');

		return {};
	}
}
