// https://tools.ietf.org/html/rfc5281 TTLS v0
// https://tools.ietf.org/html/draft-funk-eap-ttls-v1-00 TTLS v1 (not implemented)
/* eslint-disable no-bitwise */
import * as tls from 'tls';
import NodeCache from 'node-cache';
import radius from 'radius';

import { encodeTunnelPW, ITLSServer, startTLSServer } from '../../../../tls/crypt.js';
import {
	IPacket,
	IPacketAttributes,
	IPacketHandler,
	IPacketHandlerResult,
	PacketResponseCode,
} from '../../../../interfaces/PacketHandler.js';
import { MAX_RADIUS_ATTRIBUTE_SIZE, newDeferredPromise } from '../../../../helpers.js';
import { EAPMessageType, IEAPMethod } from '../../../../interfaces/EAPMethod.js';
import { IAuthentication } from '../../../../interfaces/Authentication.js';
import { IContextLogger, ILogger } from '../../../../interfaces/Logger.js';

function tlsHasExportKeyingMaterial(tlsSocket): tlsSocket is {
	exportKeyingMaterial: (length: number, label: string, context?: Buffer) => Buffer;
} {
	return typeof tlsSocket.exportKeyingMaterial === 'function';
}

interface IAVPEntry {
	type: number;
	flags: string;
	decodedFlags: {
		V: boolean;
		M: boolean;
	};
	length: number;
	vendorId?: number;
	data: Buffer;
}

export class EAPTTLS implements IEAPMethod {
	private lastProcessedIdentifier = new NodeCache({ useClones: false, stdTTL: 60 });

	// { [key: string]: Buffer } = {};
	private queueData = new NodeCache({ useClones: false, stdTTL: 60 }); // queue data maximum for 60 seconds

	private openTLSSockets = new NodeCache({ useClones: false, stdTTL: 3600 }); // keep sockets for about one hour

	private logger: IContextLogger;

	getEAPType(): number {
		return EAPMessageType.TTLS;
	}

	identify(identifier: number, stateID: string): IPacketHandlerResult {
		/**
		 *  Flags
		 *         0   1   2   3   4   5   6   7
		 *       +---+---+---+---+---+---+---+---+
		 *       | L | M | S | R | R |     V     |
		 *       +---+---+---+---+---+---+---+---+
		 *
		 *       L = Length included
		 *       M = More fragments
		 *       S = Start
		 *       R = Reserved
		 *       V = Version (000 for EAP-TTLSv0)
		 *
		 *  0x20 => means start (=00100000)
		 */
		return this.buildEAPTTLSResponse(identifier, 21, 0x20, stateID);
	}

	constructor(
		private authentication: IAuthentication,
		private tlsOptions: tls.SecureContextOptions,
		private innerTunnel: IPacketHandler,
		logger: ILogger,
		private secret: string,
		private vlan?: number
	) {
		this.logger = logger.context('EAPTTLS');
	}

	private buildEAPTTLS(
		identifier: number,
		msgType = EAPMessageType.TTLS,
		msgFlags = 0x00,
		stateID: string,
		data?: Buffer,
		newResponse = true,
		maxSize = (MAX_RADIUS_ATTRIBUTE_SIZE - 5) * 4
	): Buffer {
		this.logger.debug('maxSize', data?.length, ' > ', maxSize);

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

		let buffer = Buffer.from([
			1, // request
			identifier + 1, // increase id by 1
			0, // length (1/2)
			0, //  length (2/2)
			msgType, // 1 = identity, 21 = EAP-TTLS, 2 = notificaiton, 4 = md5-challenge, 3 = NAK
			flags, // flags: 000000 (L include lenghts, M .. more to come)
		]);

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

		this.logger.debug('<<<<<<<<<<<< EAP RESPONSE TO CLIENT', {
			code: 1,
			identifier: identifier + 1,
			includeLength,
			dataLength: (data && data.byteLength) || 0,
			msgType: msgType.toString(10),
			flags: `00000000${flags.toString(2)}`.substr(-8),
			data,
		});

		if (dataToQueue) {
			// we couldn't send all at once, queue the rest and send later
			this.queueData.set(stateID, dataToQueue);
		} else {
			this.queueData.del(stateID);
		}

		return resBuffer;
	}

	private buildEAPTTLSResponse(
		identifier: number,
		msgType = EAPMessageType.TTLS,
		msgFlags = 0x00,
		stateID: string,
		data?: Buffer,
		newResponse = true
	): IPacketHandlerResult {
		const resBuffer = this.buildEAPTTLS(identifier, msgType, msgFlags, stateID, data, newResponse);

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

	decodeTTLSMessage(msg: Buffer) {
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
		const identifier = msg.slice(1, 2).readUInt8(0);
		const flags = msg.slice(5, 6).readUInt8(0); // .toString('hex');
		/*
			0   1   2   3   4   5   6   7
		+---+---+---+---+---+---+---+---+
		| L | M | S | R | R |     V     |
		+---+---+---+---+---+---+---+---+

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
		const data = msg.slice(decodedFlags.lengthIncluded ? 10 : 6).slice(0, msglength);

		this.logger.debug('>>>>>>>>>>>> REQUEST FROM CLIENT: EAP TTLS', {
			flags: `00000000${flags.toString(2)}`.substr(-8),
			decodedFlags,
			identifier,
			msglengthBuffer: msg.length,
			msglength,
			data,
			// dataStr: data.toString()
		});

		return {
			decodedFlags,
			msglength,
			data,
		};
	}

	authResponse(
		identifier: number,
		success: boolean,
		socket: tls.TLSSocket,
		packet: IPacket
	): IPacketHandlerResult {
		const buffer = Buffer.from([
			success ? 3 : 4, // 3.. success, 4... failure
			identifier, // + 1 (do use same identifier as before for final message)
			0, // length (1/2)
			4, //  length (2/2)
		]);

		const attributes: any[] = [];
		attributes.push(['EAP-Message', buffer]);

		/* do not send username on auth response
		if (packet.attributes && packet.attributes['User-Name']) {
			// reappend username to response
			attributes.push(['User-Name', packet.attributes['User-Name'].toString()]);
		} */

		if (success && this.vlan !== undefined) {
			// Tunnel-Pvt-Group-ID (81)
			/**
			 *  A summary of the Tunnel-Private-Group-ID Attribute format is shown
			 *    below.  The fields are transmitted from left to right.
			 *
			 *     0                   1                   2                   3
			 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *    |      Type     |    Length     |     Tag       |   String ...
			 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *
			 *    Type
			 *       81 for Tunnel-Private-Group-ID.
			 *
			 *    Length
			 *       >= 3
			 *
			 *    Tag
			 *       The Tag field is one octet in length and is intended to provide a
			 *       means of grouping attributes in the same packet which refer to the
			 *       same tunnel.  If the value of the Tag field is greater than 0x00
			 *       and less than or equal to 0x1F, it SHOULD be interpreted as
			 *       indicating which tunnel (of several alternatives) this attribute
			 *       pertains.  If the Tag field is greater than 0x1F, it SHOULD be
			 *       interpreted as the first byte of the following String field.
			 *
			 *    String
			 *       This field must be present.  The group is represented by the
			 *       String field.  There is no restriction on the format of group IDs.
			 */
			attributes.push(['Tunnel-Private-Group-Id', Buffer.from(String(this.vlan))]);
			/**
			 * https://www.rfc-editor.org/rfc/rfc2868.txt
			 * // Tunnel-Type (64)
			 *  	1      Point-to-Point Tunneling Protocol (PPTP) [1]
			 *    2      Layer Two Forwarding (L2F) [2]
			 *    3      Layer Two Tunneling Protocol (L2TP) [3]
			 *    4      Ascend Tunnel Management Protocol (ATMP) [4]
			 *    5      Virtual Tunneling Protocol (VTP)
			 *    6      IP Authentication Header in the Tunnel-mode (AH) [5]
			 *    7      IP-in-IP Encapsulation (IP-IP) [6]
			 *    8      Minimal IP-in-IP Encapsulation (MIN-IP-IP) [7]
			 *    9      IP Encapsulating Security Payload in the Tunnel-mode (ESP) [8]
			 *    10     Generic Route Encapsulation (GRE) [9]
			 *    11     Bay Dial Virtual Services (DVS)
			 *    12     IP-in-IP Tunneling [10]
			 *    13		 VLAN
			 */

			attributes.push(['Tunnel-Type', Buffer.from([0x00, 0, 0, 13])]);

			/**
			 * // Tunnel-Medium-Type (65)
			 *  	1      IPv4 (IP version 4)
			 *    2      IPv6 (IP version 6)
			 *    3      NSAP
			 *    4      HDLC (8-bit multidrop)
			 *    5      BBN 1822
			 *    6      802 (includes all 802 media plus Ethernet "canonical format")
			 *    7      E.163 (POTS)
			 *    8      E.164 (SMDS, Frame Relay, ATM)
			 */

			attributes.push(['Tunnel-Medium-Type', Buffer.from([0x00, 0, 0, 6])]);

			attributes.push([
				'Framed-Protocol', // 7
				Buffer.from([0, 0, 0, 1]),
			]);

			attributes.push([
				'Service-Type', // 6
				Buffer.from([0, 0, 0, 2]),
			]);
		}

		if (tlsHasExportKeyingMaterial(socket)) {
			const keyingMaterial = socket.exportKeyingMaterial(128, 'ttls keying material');

			if (!packet.authenticator) {
				throw new Error('FATAL: no packet authenticator variable set');
			}

			attributes.push([
				'Vendor-Specific',
				311,
				[[16, encodeTunnelPW(keyingMaterial.slice(64), packet.authenticator, this.secret)]],
			]); //  MS-MPPE-Send-Key

			attributes.push([
				'Vendor-Specific',
				311,
				[[17, encodeTunnelPW(keyingMaterial.slice(0, 64), packet.authenticator, this.secret)]],
			]); // MS-MPPE-Recv-Key
		} else {
			this.logger.error(
				'FATAL: no exportKeyingMaterial method available!!!, you need latest NODE JS, see https://github.com/nodejs/node/pull/31814'
			);
		}

		return {
			code: success ? PacketResponseCode.AccessAccept : PacketResponseCode.AccessReject,
			attributes,
		};
	}

	async handleMessage(
		identifier: number,
		stateID: string,
		msg: Buffer,
		packet: IPacket
	): Promise<IPacketHandlerResult> {
		if (identifier === this.lastProcessedIdentifier.get(stateID)) {
			this.logger.debug(
				`ignoring message ${identifier}, because it's processing already... ${stateID}`
			);

			return {};
		}
		this.lastProcessedIdentifier.set(stateID, identifier);
		try {
			const { data } = this.decodeTTLSMessage(msg);

			// check if no data package is there and we have something in the queue, if so.. empty the queue first
			if (!data || data.length === 0) {
				const queuedData = this.queueData.get(stateID);
				if (queuedData instanceof Buffer && queuedData.length > 0) {
					this.logger.debug(`returning queued data for ${stateID}`);
					return this.buildEAPTTLSResponse(identifier, 21, 0x00, stateID, queuedData, false);
				}

				this.logger.debug(`empty data queue for ${stateID}`);
				return {};
			}

			let connection = this.openTLSSockets.get(stateID) as ITLSServer;

			if (!connection) {
				connection = startTLSServer(this.tlsOptions, this.logger);
				this.openTLSSockets.set(stateID, connection);

				connection.events.on('end', () => {
					// cleanup socket
					this.logger.debug('ENDING SOCKET');
					this.openTLSSockets.del(stateID);
					this.lastProcessedIdentifier.del(stateID);
				});
			}

			const sendResponsePromise = newDeferredPromise();

			const incomingMessageHandler = async (incomingData: Buffer) => {
				const ret: any = {};
				ret.attributes = {};
				ret.raw_attributes = [];

				const AVPs = this.decodeAVPs(incomingData);

				// build attributes for packet handler
				const attributes: IPacketAttributes = {};
				AVPs.forEach((avp) => {
					attributes[(radius as any).attr_id_to_name(avp.type)] = avp.data;
				});

				attributes.State = `${stateID}-inner`;

				// handle incoming package via inner tunnel
				const result = await this.innerTunnel.handlePacket(
					{
						attributes,
					},
					this.getEAPType()
				);

				this.logger.debug('inner tunnel result', result);

				if (
					result.code === PacketResponseCode.AccessReject ||
					result.code === PacketResponseCode.AccessAccept
				) {
					sendResponsePromise.resolve(
						this.authResponse(
							identifier,
							result.code === PacketResponseCode.AccessAccept,
							connection.tls,
							{
								...packet,
								attributes: {
									...packet.attributes,
									...this.transformAttributesArrayToMap(result.attributes),
								},
							}
						)
					);
					return;
				}

				const eapMessage = result.attributes?.find((attr) => attr[0] === 'EAP-Message');
				if (!eapMessage) {
					throw new Error('no eap message found');
				}

				connection.events.emit(
					'encrypt',
					this.buildAVP((radius as any).attr_name_to_id('EAP-Message'), eapMessage[1] as Buffer)
				);
			};

			let tlsbuf = Buffer.from([]);
			let sendChunk = Buffer.from([]);

			const responseHandler = (encryptedResponseData: Buffer) => {
				// Parse TLS record header
				tlsbuf = Buffer.concat([tlsbuf, encryptedResponseData]);

				while (tlsbuf.length > 5) {
					if (tlsbuf.length < 5) {
						// not even so much data to read a header
						this.logger.debug(`Not enough data length! tlsbuf.length = ${tlsbuf.length} < 5`);
						break;
					}

					// Parse TLS record header
					// https://datatracker.ietf.org/doc/html/rfc5246

					// SSL3_RT_CHANGE_CIPHER_SPEC      20   (x'14')
					// SSL3_RT_ALERT                   21   (x'15')
					// SSL3_RT_HANDSHAKE               22   (x'16')
					// SSL3_RT_APPLICATION_DATA        23   (x'17')
					// TLS1_RT_HEARTBEAT               24   (x'18')
					const tlsContentType = tlsbuf.readUInt8(0);

					// TLS1_VERSION           x'0301'
					// TLS1_1_VERSION         x'0302'
					// TLS1_2_VERSION         x'0303'
					const tlsVersion = tlsbuf.readUInt16BE(1);

					// Length of data in the record (excluding the header itself).
					const tlsLength = tlsbuf.readUInt16BE(3);
					this.logger.debug(
						`TLS contentType = ${tlsContentType} version = 0x${tlsVersion.toString(
							16
						)} tlsLength = ${tlsLength}, tlsBufLength = ${tlsbuf.length}`
					);

					if (tlsbuf.length < tlsLength + 5) {
						this.logger.debug(
							`Not enough data length! tlsbuf.length < ${tlsbuf.length} < ${tlsLength + 5}`
						);
						break;
					}
					sendChunk = Buffer.concat([sendChunk, tlsbuf.slice(0, tlsLength + 5)]);
					tlsbuf = tlsbuf.slice(tlsLength + 5);
				}

				this.logger.debug('Maybe it is end of TLS burst.', tlsbuf.length);
				this.logger.debug(`sendChunk sz=${sendChunk.length}`);

				this.logger.debug('complete');

				// send back...
				sendResponsePromise.resolve(
					this.buildEAPTTLSResponse(identifier, 21, 0x00, stateID, sendChunk)
				);
			};

			const checkExistingSession = (isSessionReused) => {
				if (isSessionReused) {
					this.logger.debug('secured, session reused, accept auth!');
					sendResponsePromise.resolve(this.authResponse(identifier, true, connection.tls, packet));
				}
			};

			// register event listeners
			connection.events.on('incoming', incomingMessageHandler);
			connection.events.on('response', responseHandler);
			connection.events.on('secured', checkExistingSession);

			// emit data to tls server
			connection.events.emit('decrypt', data);
			const responseData = await sendResponsePromise.promise;

			// cleanup
			connection.events.off('incoming', incomingMessageHandler);
			connection.events.off('response', responseHandler);
			connection.events.off('secured', checkExistingSession);

			// connection.events.off('secured');

			// send response
			return responseData; // this.buildEAPTTLSResponse(identifier, 21, 0x00, stateID, encryptedResponseData);
		} catch (err) {
			this.logger.error('decoding of EAP-TTLS package failed', msg, err);
			return {
				code: PacketResponseCode.AccessReject,
			};
		} finally {
			this.lastProcessedIdentifier.set(stateID, undefined);
		}
	}

	private transformAttributesArrayToMap(attributes: [string, Buffer | string][] | undefined) {
		const result = {};
		attributes?.forEach(([key, value]) => {
			result[key] = value;
		});
		return result;
	}

	private decodeAVPs(buffer: Buffer): IAVPEntry[] {
		const results: {
			type: number;
			flags: string;
			decodedFlags: {
				V: boolean;
				M: boolean;
			};
			length: number;
			vendorId?: number;
			data: Buffer;
		}[] = [];

		let currentBuffer = buffer;
		do {
			/**
			 * 4.1.  AVP Header

						 The fields in the AVP header MUST be sent in network byte order.  The
						 format of the header is:

							0                   1                   2                   3
							0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
						 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						 |                           AVP Code                            |
						 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						 |V M P r r r r r|                  AVP Length                   |
						 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						 |                        Vendor-ID (opt)                        |
						 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						 |    Data ...
						 +-+-+-+-+-+-+-+-+
			 */
			const type = currentBuffer.slice(0, 4).readUInt32BE(0);
			const flags = currentBuffer.slice(4, 5).readUInt8(0);
			const decodedFlags = {
				// L
				V: !!(flags & 0b10000000),
				// M
				M: !!(flags & 0b01000000),
			};

			// const length = buffer.slice(5, 8).readUInt16BE(0); // actually a Int24BE
			const length = currentBuffer.slice(6, 8).readUInt16BE(0); // actually a Int24BE

			let vendorId;
			let data;
			if (decodedFlags.V) {
				// V flag set
				vendorId = currentBuffer.slice(8, 12).readUInt32BE(0);
				data = currentBuffer.slice(12, length);
			} else {
				data = currentBuffer.slice(8, length);
			}

			results.push({
				type,
				flags: `00000000${flags.toString(2)}`.substr(-8),
				decodedFlags,
				length,
				vendorId,
				data,
			});

			// ensure length is a multiple of 4 octect
			let totalAVPSize = length;
			while (totalAVPSize % 4 !== 0) {
				totalAVPSize += 1;
			}
			currentBuffer = currentBuffer.slice(totalAVPSize);
		} while (currentBuffer.length > 0);

		return results;
	}

	private buildAVP(
		code: number,
		data: Buffer,
		flags: { VendorSpecific?: boolean; Mandatory?: boolean } = { Mandatory: true }
	) {
		/**
		 * 4.1.  AVP Header

						 The fields in the AVP header MUST be sent in network byte order.  The
						 format of the header is:

							0                   1                   2                   3
							0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
						 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						 |                           AVP Code                            |
						 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						 |V M r r r r r r|                  AVP Length                   |
						 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						 |                        Vendor-ID (opt)                        |
						 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						 |    Data ...
						 +-+-+-+-+-+-+-+-+
		 */
		let AVP = Buffer.alloc(8);

		AVP.writeInt32BE(code, 0); // EAP-Message
		/**
		 * The 'V' (Vendor-Specific) bit indicates whether the optional
      Vendor-ID field is present.  When set to 1, the Vendor-ID field is
      present and the AVP Code is interpreted according to the namespace
      defined by the vendor indicated in the Vendor-ID field.

      The 'M' (Mandatory) bit indicates whether support of the AVP is
      required.  If this bit is set to 0, this indicates that the AVP
      may be safely ignored if the receiving party does not understand
      or support it.  If set to 1, this indicates that the receiving
      party MUST fail the negotiation if it does not understand the AVP;
      for a TTLS server, this would imply returning EAP-Failure, for a
      client, this would imply abandoning the negotiation.
		 */
		let flagValue = 0;
		if (flags.VendorSpecific) {
			flagValue += 0b10000000;
		}
		if (flags.Mandatory) {
			flagValue += 0b01000000;
		}

		// this.logger.debug('flagValue', flagValue, `00000000${flagValue.toString(2)}`.substr(-8));

		AVP.writeInt8(flagValue, 4); // flags (set V..)

		AVP = Buffer.concat([AVP, data]); // , Buffer.from('\0')]);

		AVP.writeInt16BE(AVP.byteLength, 6); // write size (actually we would need a Int24BE here, but it is good to go with 16bits)

		// fill up with 0x00 till we have % 4
		while (AVP.length % 4 !== 0) {
			AVP = Buffer.concat([AVP, Buffer.from([0x00])]);
		}

		return AVP;
	}
}
