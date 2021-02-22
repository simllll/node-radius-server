/* eslint-disable no-bitwise */
import debug from 'debug';

import { IPacket, IPacketHandlerResult, PacketResponseCode } from '../../../types/PacketHandler';
import { IBuildEAP, IEAPHeader, EAPMessageType, EAPRequestType } from '../../../types/EAPMethod';
import { MAX_RADIUS_ATTRIBUTE_SIZE } from '../../../helpers';

const log = debug('radius:eap:helper');

export function buildEAP(
	identifier: number,
	msgType: number,
	data?: Buffer,
	reuqestType = EAPRequestType.REQUEST,
	msgFlags = 0x00,
	newResponse = true,
	maxSize = (MAX_RADIUS_ATTRIBUTE_SIZE - 5) * 4
): IBuildEAP {
	log('maxSize', maxSize);

	/* it's the first one and we have more, therefore include length */
	const includeLength = maxSize > 0 && data && newResponse && data.length > maxSize;

	// extract data party
	const dataToSend = maxSize > 0 ? data && data.length > 0 && data.slice(0, maxSize) : data;
	const dataToQueue = maxSize > 0 && data && data.length > maxSize && data.slice(maxSize);

	/*
		0 1 2 3 4 5 6 7 8
		+-+-+-+-+-+-+-+-+
		|L M R R R R R R|
		+-+-+-+-+-+-+-+-+

		L = Length included
		M = More fragments
		R = Reserved

		The L bit (length included) is set to indicate the presence of the
		four-octet TLS Message Length field, and MUST be set for the first
		fragment of a fragmented TLS message or set of messages.  The M
		bit (more fragments) is set on all but the last fragment.
				Implementations of this specification MUST set the reserved bits
		to zero, and MUST ignore them on reception.
	*/

	const flags =
		msgFlags +
		(includeLength ? 0b10000000 : 0) + // set L bit
		(dataToQueue && dataToQueue.length > 0 ? 0b01000000 : 0); // we have more data to come, set M bit

	const msg = [
		reuqestType, // 1 = request, 2 = response, 3 = success, 4 = falure
		// identifier + 1,
		[EAPMessageType.MD5, EAPMessageType.TTLS, EAPMessageType.PEAP].includes(msgType)
			? identifier + 1
			: identifier, // increase id by 1
		0, // length (1/2)
		0, //  length (2/2)
		msgType, // 1 = identity, 21 = EAP-TTLS, 2 = notificaiton, 4 = md5-challenge, 3 = NAK
	];

	if ([EAPMessageType.TTLS, EAPMessageType.PEAP].includes(msgType)) {
		msg.push(flags); // flags: 000000 (L include lenghts, M .. more to come)
	}

	let buffer = Buffer.from(msg);

	// append length
	if (includeLength && data) {
		const length = Buffer.alloc(4);
		length.writeInt32BE(data.byteLength, 0);

		buffer = Buffer.concat([buffer, length]);
	}

	// build final buffer with data
	const resBuffer = dataToSend ? Buffer.concat([buffer, dataToSend]) : buffer;

	// set EAP length header
	resBuffer.writeUInt16BE(resBuffer.byteLength, 2);

	log('<<<<<<<<<<<< EAP RESPONSE TO CLIENT', {
		code: 1,
		identifier: identifier + 1,
		includeLength,
		dataLength: (data && data.byteLength) || 0,
		msgType: msgType.toString(10),
		flags: `00000000${flags.toString(2)}`.substr(-8),
		data,
	});

	return { resBuffer, dataToQueue };
}

/**
 *
 * @param data
 * @param msgType 1 = identity, 21 = EAP-TTLS, 2 = notification, 4 = md5-challenge, 3 = NAK
 */
export function buildEAPResponse(
	identifier: number,
	msgType: number,
	data?: Buffer
): IPacketHandlerResult {
	const { resBuffer } = buildEAP(identifier, msgType, data);
	return {
		code: PacketResponseCode.AccessChallenge,
		attributes: [['EAP-Message', resBuffer]],
	};
}

export function decodeEAPHeader(msg: Buffer, rawData = false): IEAPHeader {
	/**
	 * parse msg according to this:
		0                   1                   2                   3
		0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |     Code      |  Identifier   |            Length             |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |     Type      |  Type-Data ...
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	 */

	/*
	code:
		1       Request
		2       Response
		3       Success
		4       Failure
	*/
	const code = msg.slice(0, 1).readUInt8(0);
	/* identifier is a number */
	const identifier = msg.slice(1, 2).readUInt8(0);
	const length = msg.slice(2, 4).readUInt16BE(0);
	/* EAP type:
		1       Identity
		2       Notification
		3       NAK
		4       MD5-Challenge
		5       One Time password
		6       Generic Token Card
	*/
	const type = msg.slice(4, 5).readUInt8(0);
	let data = msg.slice(5);
	const flags = msg.slice(5, 6).readUInt8(0);

	/*
	L = Length included
		M = More fragments
		S = Start
		R = Reserved
		V = Version (000 for EAP-TTLSv0)
		*/
	const decodedFlags = {
		// L
		lengthIncluded: !!(flags & 0b10000000),
		// M
		moreFragments: !!(flags & 0b01000000),
		// S
		start: !!(flags & 0b00100000),
		// R
		// reserved: flags & 0b00011000,
		// V
		version: flags & 0b00000111,
	};

	let msglength;
	if (decodedFlags.lengthIncluded) {
		msglength = msg.slice(6, 10).readUInt32BE(0); // .readDoubleLE(0); // .toString('hex');
	}
	if (!rawData) {
		data = msg.slice(decodedFlags.lengthIncluded ? 10 : 6).slice(0, msglength);
	}

	log('>>>>>>>>>>>> EAP REQUEST FROM CLIENT', {
		flags: `00000000${flags.toString(2)}`.substr(-8),
		decodedFlags,
		identifier,
		msglengthBuffer: msg.length,
		msglength,
		data,
		// dataStr: data.toString()
	});

	return {
		code,
		identifier,
		length,
		msglength,
		type,
		data,
		decodedFlags,
	};
}

export function authResponse(
	identifier: number,
	success: boolean,
	packet: IPacket,
	extraAttributes?: any[]
): IPacketHandlerResult {
	const buffer = Buffer.from([
		success ? 3 : 4, // 3.. success, 4... failure
		identifier + 1,
		0, // length (1/2)
		4, //  length (2/2)
	]);

	const attributes: any[] = [];
	attributes.push(['EAP-Message', buffer]);

	if (packet.attributes && packet.attributes['User-Name']) {
		// reappend username to response
		attributes.push(['User-Name', packet.attributes['User-Name'].toString()]);
	}

	if (extraAttributes) {
		attributes.concat(extraAttributes);
	}

	return {
		code: success ? PacketResponseCode.AccessAccept : PacketResponseCode.AccessReject,
		attributes,
	};
}
