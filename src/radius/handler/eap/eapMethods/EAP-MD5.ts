// https://tools.ietf.org/html/rfc5281 TTLS v0
// https://tools.ietf.org/html/draft-funk-eap-ttls-v1-00 TTLS v1 (not implemented)
/* eslint-disable no-bitwise */
import { RadiusPacket } from 'radius';
import { IPacketHandlerResult } from '../../../../interfaces/PacketHandler.js';
import { IEAPMethod } from '../../../../interfaces/EAPMethod.js';
import { IAuthentication } from '../../../../interfaces/Authentication.js';
import { IContextLogger, ILogger } from '../../../../interfaces/Logger.js';

export class EAPMD5 implements IEAPMethod {
	private logger: IContextLogger;

	getEAPType(): number {
		return 4;
	}

	identify(_identifier: number, _stateID: string): IPacketHandlerResult {
		// NOT IMPLEMENTED
		return {};
	}

	constructor(private authentication: IAuthentication, logger: ILogger) {
		this.logger = logger.context('EAPMD5');
	}

	async handleMessage(
		_identifier: number,
		_stateID: string,
		_msg: Buffer,
		_orgRadiusPacket: RadiusPacket
	): Promise<IPacketHandlerResult> {
		// not implemented

		this.logger.debug('eap md5 not implemented...');

		return {};
	}
}
