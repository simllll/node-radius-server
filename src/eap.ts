// https://tools.ietf.org/html/rfc3748#section-4.1

// https://tools.ietf.org/html/rfc5281 TTLS v0
// https://tools.ietf.org/html/draft-funk-eap-ttls-v1-00 TTLS v1 (not implemented)
import { IResponseHandlers, ResponseHandler } from './types/Handler';
import { EAPTTLS } from './eap/eap-ttls';
import { MAX_RADIUS_ATTRIBUTE_SIZE } from './helpers';

export class EAPHandler {
	eapTTLS: EAPTTLS;

	constructor() {
		this.eapTTLS = new EAPTTLS(this.sendEAPResponse);
	}

	/**
	 *
	 * @param data
	 * @param type 1 = identity, 21 = EAP-TTLS, 2 = notification, 4 = md5-challenge, 3 = NAK
	 */
	private async sendEAPResponse(
		response: ResponseHandler,
		identifier: number,
		data?: Buffer,
		msgType = 21,
		msgFlags = 0x00
	) {
		let i = 0;

		const maxSize = (MAX_RADIUS_ATTRIBUTE_SIZE - 5) * 4;

		let sentDataSize = 0;

		let currentIdentifier = identifier;
		let currentResponse = response;

		do {
			// SLICE

			// const fragmentMaxPart =
			// data && (i + 1) * maxFragmentSize > data.length ? (i + 1) * maxFragmentSize : undefined;

			const dataPart = data && data.length > 0 && data.slice(sentDataSize, sentDataSize + maxSize);

			/* it's the first one and we have more, therefore include length */
			const includeLength = data && i === 0 && sentDataSize < data.length;

			sentDataSize += maxSize;

			i += 1;

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
				(data && sentDataSize < data.length /* we have more */ ? 0b01000000 : 0); // set M bit

			currentIdentifier++;

			let buffer = Buffer.from([
				1, // request
				currentIdentifier,
				0, // length (1/2)
				0, //  length (2/2)
				msgType, // 1 = identity, 21 = EAP-TTLS, 2 = notificaiton, 4 = md5-challenge, 3 = NAK
				flags // flags: 000000 (L include lenghts, M .. more to come)
			]);

			// append length
			if (includeLength && data) {
				const length = Buffer.alloc(4);
				length.writeInt32BE(data.byteLength, 0);

				buffer = Buffer.concat([buffer, length]);
			}

			const resBuffer = dataPart ? Buffer.concat([buffer, dataPart]) : buffer;
			resBuffer.writeUInt16BE(resBuffer.byteLength, 2);

			console.log('<<<<<<<<<<<< EAP RESPONSE TO CLIENT', {
				code: 1,
				currentIdentifier,
				includeLength,
				length: (data && data.byteLength) || 0,
				msgType: msgType.toString(10),
				flags: `00000000${flags.toString(2)}`.substr(-8),
				data
			});

			//    uffer.from([1,identifier, 0, 0, 21, 0]);
			// buffer.writeUInt16BE(sslResponse.length, 2); // length
			// buffer.writeInt8(21, 4); // eap-ttls
			// buffer.writeInt8(0, 5); // flags

			console.log('sending message with identifier', currentIdentifier);
			({ identifier: currentIdentifier, response: currentResponse } = await currentResponse(
				resBuffer
			));
			console.log('next message got identifier', currentIdentifier);
		} while (data && sentDataSize < data.length);

		console.log('DONE', sentDataSize, data && data.length);
	}

	handleEAPMessage(msg: Buffer, state: string, handlers: IResponseHandlers) {
		// const b = Buffer.from([2,0x242,0x0,0x18,0x1,0x115,0x105,0x109,0x111,0x110,0x46,0x116,0x114,0x101,0x116,0x116,0x101,0x114]);
		// const msg = Buffer.from([2, 162, 0, 18, 1, 115, 105, 109, 111, 110, 46, 116, 114, 101, 116, 116, 101, 114])

		/*
        1       Request
        2       Response
        3       Success
        4       Failure
         */

		const code = msg.slice(0, 1).readUInt8(0);
		const identifier = msg.slice(1, 2).readUInt8(0); // .toString('hex');
		// const length = msg.slice(2, 4).readInt16BE(0); // .toString('binary');
		const type = msg.slice(4, 5).readUInt8(0); // .slice(3,0x5).toString('hex');

		/*
        console.log("CODE", code);
        console.log('ID', identifier);
        console.log('length', length);
         */

		switch (code) {
			case 1: // for request
			case 2: // for response
				switch (type) {
					case 1: // identifiy
						/**
						 * The EAP-TTLS packet format is shown below.  The fields are
						 transmitted left to right.

						 0                   1                   2                   3
						 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
						 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						 |     Code      |   Identifier  |            Length             |
						 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						 |     Type      |     Flags     |        Message Length
						 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						 Message Length         |             Data...
						 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						 */
						console.log('>>>>>>>>>>>> REQUEST FROM CLIENT: IDENTIFY', {});

						this.sendEAPResponse(handlers.response, identifier, undefined, 21, 0x20);

						/*
                        handlers.response(
                            Buffer.from([
                                1, // request
                                identifier + 1,
                                0, // length (1/2)
                                6, // length (2/2)
                                21, // EAP-TTLS
                                0x20 // flags: 001000 start flag
                            ])
                        ); */
						break;
					case 21: // EAP TTLS
						this.eapTTLS.handleMessage(msg, state, handlers, identifier);
						break;
					case 3: // nak
						// this.sendEAPResponse(handlers.response, identifier, undefined, 3);
						break;
					case 2: // notification
						console.log('>>>>>>>>>>>> REQUEST FROM CLIENT: notification', {});
						console.info('notification');
						break;
					case 4: // md5-challenge
						console.log('>>>>>>>>>>>> REQUEST FROM CLIENT: md5-challenge', {});

						console.info('md5-challenge');
						break;
					case 254: // expanded type
						console.error('not implemented type', type);

						break;

					default:
						// we do not support this auth type, ask for TTLS
						console.error('unsupported type', type, 'requesting TTLS (21)');

						this.sendEAPResponse(handlers.response, identifier, Buffer.from([21]), 3);

						break;
				}
				break;
			case 3:
				console.log('Client Auth Success');
				break;
			case 4:
				console.log('Client Auth FAILURE');
				break;
			default:
				break;
			// silently ignor;
		}
	}
}
