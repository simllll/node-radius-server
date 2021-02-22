// https://tools.ietf.org/html/draft-josefsson-pppext-eap-tls-eap-06
/* eslint-disable no-bitwise */
import debug from 'debug';
import * as crypto from 'crypto';
import * as NodeCache from 'node-cache';
import {
	IPacket,
	// IPacketAttributes,
	// IPacketHandler,
	IPacketHandlerResult,
	PacketResponseCode,
} from '../../../../types/PacketHandler';
import { MAX_RADIUS_ATTRIBUTE_SIZE } from '../../../../helpers';
import { IEAPMethod, EAPMessageType } from '../../../../types/EAPMethod';
import { IAuthentication } from '../../../../types/Authentication';
import { buildEAP, decodeEAPHeader, authResponse } from '../EAPHelper';

const log = debug('radius:eap:md5');

export class EAPMD5 implements IEAPMethod {
	private challenges = new NodeCache({ useClones: false, stdTTL: 60 });

	getEAPType(): number {
		return EAPMessageType.MD5;
	}

	identify(identifier: number, stateID: string): IPacketHandlerResult {
		return this.buildEAPMD5Response(identifier, stateID);
	}

	constructor(private authentication: IAuthentication) {}

	private buildEAPMD5Response(
		identifier: number,
		stateID: string,
		msgType = EAPMessageType.MD5
	): IPacketHandlerResult {
		const challenge = crypto.randomBytes(16);
		this.challenges.set(stateID, challenge);
		const challengeData = Buffer.concat([Buffer.from([16]), challenge]);
		const { resBuffer } = buildEAP(identifier, msgType, challengeData);

		const attributes: any = [['State', Buffer.from(stateID)]];
		let sentDataSize = 0;
		do {
			if (resBuffer.length > 0) {
				attributes.push([
					'EAP-Message',
					resBuffer.slice(sentDataSize, sentDataSize + MAX_RADIUS_ATTRIBUTE_SIZE),
				]);
				sentDataSize += MAX_RADIUS_ATTRIBUTE_SIZE;
			}
		} while (sentDataSize < resBuffer.length);

		return {
			code: PacketResponseCode.AccessChallenge,
			attributes,
		};
	}

	async handleMessage(
		identifier: number,
		stateID: string,
		msg: Buffer,
		packet: IPacket
	): Promise<IPacketHandlerResult> {
		if (identifier === this.challenges.get(stateID)) {
			log(`ignoring message ${identifier}, because it's processing already... ${stateID}`);

			return {};
		}
		try {
			const { data } = decodeEAPHeader(msg);

			const username = packet.attributes['User-Name'];
			const challenge: Buffer | undefined = this.challenges.get(stateID);

			if (!username) {
				throw new Error('no username');
			}

			if (!challenge) {
				throw new Error('no challenge');
			}

			log('username', username, username.toString());
			log('challenge', challenge, challenge.toString('hex'));

			const success = await this.authentication.authenticateMD5Challenge(
				identifier,
				username.toString(),
				challenge,
				data
			);

			return authResponse(identifier, success, packet);
		} catch (err) {
			console.error('decoding of EAP-MD5 package failed', msg, err);
			return {
				code: PacketResponseCode.AccessReject,
			};
		} finally {
			this.challenges.del(stateID);
		}
	}
}
