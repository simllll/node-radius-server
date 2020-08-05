// https://tools.ietf.org/html/rfc5281 TTLS v0
// https://tools.ietf.org/html/draft-funk-eap-ttls-v1-00 TTLS v1 (not implemented)
/* eslint-disable no-bitwise */
import * as tls from 'tls';
import * as NodeCache from 'node-cache';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import { attr_id_to_name, attr_name_to_id } from 'radius';
import debug from 'debug';

import { encodeTunnelPW, ITLSServer, startTLSServer } from '../../../../tls/crypt';
import {
	IPacket,
	IPacketAttributes,
	IPacketHandler,
	IPacketHandlerResult,
	PacketResponseCode,
} from '../../../../types/PacketHandler';
import { MAX_RADIUS_ATTRIBUTE_SIZE, newDeferredPromise } from '../../../../helpers';
import { IEAPMethod } from '../../../../types/EAPMethod';
import { IAuthentication } from '../../../../types/Authentication';
import { secret } from '../../../../../config';

const log = debug('radius:eap:ttls');

function tlsHasExportKeyingMaterial(
	tlsSocket
): tlsSocket is {
	exportKeyingMaterial: (length: number, label: string, context?: Buffer) => Buffer;
} {
	return typeof (tlsSocket as any).exportKeyingMaterial === 'function';
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

	getEAPType(): number {
		return 21;
	}

	identify(identifier: number, stateID: string): IPacketHandlerResult {
		return this.buildEAPTTLSResponse(identifier, 21, 0x20, stateID);
	}

	constructor(private authentication: IAuthentication, private innerTunnel: IPacketHandler) {}

	private buildEAPTTLS(
		identifier: number,
		msgType = 21,
		msgFlags = 0x00,
		stateID: string,
		data?: Buffer,
		newResponse = true,
		maxSize = (MAX_RADIUS_ATTRIBUTE_SIZE - 5) * 4
	): Buffer {
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

		log('<<<<<<<<<<<< EAP RESPONSE TO CLIENT', {
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
		msgType = 21,
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

		log('>>>>>>>>>>>> REQUEST FROM CLIENT: EAP TTLS', {
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

		if (tlsHasExportKeyingMaterial(socket)) {
			const keyingMaterial = socket.exportKeyingMaterial(128, 'ttls keying material');

			if (!packet.authenticator) {
				throw new Error('FATAL: no packet authenticator variable set');
			}

			attributes.push([
				'Vendor-Specific',
				311,
				[[16, encodeTunnelPW(keyingMaterial.slice(64), packet.authenticator, secret)]],
			]); //  MS-MPPE-Send-Key

			attributes.push([
				'Vendor-Specific',
				311,
				[[17, encodeTunnelPW(keyingMaterial.slice(0, 64), packet.authenticator, secret)]],
			]); // MS-MPPE-Recv-Key
		} else {
			console.error(
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
			log(`ignoring message ${identifier}, because it's processing already... ${stateID}`);

			return {};
		}
		this.lastProcessedIdentifier.set(stateID, identifier);
		try {
			const { data } = this.decodeTTLSMessage(msg);

			// check if no data package is there and we have something in the queue, if so.. empty the queue first
			if (!data || data.length === 0) {
				const queuedData = this.queueData.get(stateID);
				if (queuedData instanceof Buffer && queuedData.length > 0) {
					log(`returning queued data for ${stateID}`);
					return this.buildEAPTTLSResponse(identifier, 21, 0x00, stateID, queuedData, false);
				}

				log(`empty data queue for ${stateID}`);
				return {};
			}

			let connection = this.openTLSSockets.get(stateID) as ITLSServer;

			if (!connection) {
				connection = startTLSServer();
				this.openTLSSockets.set(stateID, connection);

				connection.events.on('end', () => {
					// cleanup socket
					log('ENDING SOCKET');
					this.openTLSSockets.del(stateID);
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
					attributes[attr_id_to_name(avp.type)] = avp.data;
				});

				attributes.State = `${stateID}-inner`;

				// handle incoming package via inner tunnel
				const result = await this.innerTunnel.handlePacket(
					{
						attributes,
					},
					this.getEAPType()
				);

				log('inner tunnel result', result);

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
					this.buildAVP(attr_name_to_id('EAP-Message'), eapMessage[1] as Buffer)
				);
			};

			const responseHandler = (encryptedResponseData: Buffer) => {
				log('complete');
				// send back...
				sendResponsePromise.resolve(
					this.buildEAPTTLSResponse(identifier, 21, 0x00, stateID, encryptedResponseData)
				);
			};

			const checkExistingSession = (isSessionReused) => {
				if (isSessionReused) {
					log('secured, session reused, accept auth!');
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
			console.error('decoding of EAP-TTLS package failed', msg, err);
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

		// log('flagValue', flagValue, `00000000${flagValue.toString(2)}`.substr(-8));

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
