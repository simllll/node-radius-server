import { IPacketHandlerResult, PacketResponseCode } from '../../../interfaces/PacketHandler.js';
import { EAPMessageType } from '../../../interfaces/EAPMethod.js';

export function buildEAP(identifier: number, msgType: EAPMessageType, data?: Buffer) {
	/** build a package according to this:
			0                   1                   2                   3
			0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 |     Code      |  Identifier   |            Length             |
		 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 |     Type      |  Type-Data ...
		 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	 */
	const buffer = Buffer.from([
		1, // request
		identifier,
		0, // length (1/2)
		0, //  length (2/2)
		msgType, // 1 = identity, 21 = EAP-TTLS, 2 = notificaiton, 4 = md5-challenge, 3 = NAK
	]);

	const resBuffer = data ? Buffer.concat([buffer, data]) : buffer;

	// set EAP length header
	resBuffer.writeUInt16BE(resBuffer.byteLength, 2);

	return resBuffer;
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
	return {
		code: PacketResponseCode.AccessChallenge,
		attributes: [['EAP-Message', buildEAP(identifier, msgType, data)]],
	};
}

export function decodeEAPHeader(msg: Buffer) {
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
	/* EAP type */
	const type = msg.slice(4, 5).readUInt8(0);
	const data = msg.slice(5);

	return {
		code,
		identifier,
		length,
		type,
		data,
	};
}
