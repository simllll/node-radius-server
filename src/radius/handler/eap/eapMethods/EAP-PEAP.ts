// https://tools.ietf.org/html/draft-josefsson-pppext-eap-tls-eap-06
/* eslint-disable no-bitwise */
import * as tls from 'tls';
import * as NodeCache from 'node-cache';
import * as crypto from 'crypto';
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
import { IEAPMethod, EAPMessageType, EAPRequestType } from '../../../../types/EAPMethod';
import { IAuthentication } from '../../../../types/Authentication';
import { secret } from '../../../../../config';
import { buildEAP, decodeEAPHeader, authResponse } from '../EAPHelper';

const log = debug('radius:eap:peap');

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

export class EAPPEAP implements IEAPMethod {
	private lastProcessedIdentifier = new NodeCache({ useClones: false, stdTTL: 60 });

	// { [key: string]: Buffer } = {};
	private queueData = new NodeCache({ useClones: false, stdTTL: 60 }); // queue data maximum for 60 seconds

	private openTLSSockets = new NodeCache({ useClones: false, stdTTL: 3600 }); // keep sockets for about one hour

	getEAPType(): number {
		return EAPMessageType.PEAP;
	}

	identify(identifier: number, stateID: string): IPacketHandlerResult {
		return this.buildEAPPEAPResponse(identifier, EAPMessageType.PEAP, 0x20, stateID);
	}

	constructor(private authentication: IAuthentication, private innerTunnel: IPacketHandler) {}

	private buildEAPPEAPResponse(
		identifier: number,
		msgType = EAPMessageType.PEAP,
		msgFlags = 0x00,
		stateID: string,
		data?: Buffer,
		newResponse = true,
		extraAttributes?: any[]
	): IPacketHandlerResult {
		const { resBuffer, dataToQueue } = buildEAP(
			identifier,
			msgType,
			data,
			EAPRequestType.REQUEST,
			msgFlags,
			newResponse
		);

		if (dataToQueue) {
			// we couldn't send all at once, queue the rest and send later
			this.queueData.set(stateID, dataToQueue);
		} else {
			this.queueData.del(stateID);
		}

		let attributes: any = [['State', Buffer.from(stateID)]]; // Calling-Station-Id
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

		if (extraAttributes) {
			attributes = attributes.concat(extraAttributes);
		}

		return {
			code: PacketResponseCode.AccessChallenge,
			attributes,
		};
	}

	peapExtraAttributes(socket: tls.TLSSocket, packet: IPacket): any[] {
		const extraAttributes: any[] = [];
		if (tlsHasExportKeyingMaterial(socket)) {
			const keyingMaterial = socket.exportKeyingMaterial(128, 'ttls keying material');

			if (!packet.authenticator) {
				throw new Error('FATAL: no packet authenticator variable set');
			}

			extraAttributes.push([
				'Vendor-Specific',
				311,
				[[16, encodeTunnelPW(keyingMaterial.slice(64), packet.authenticator, secret)]],
			]); //  MS-MPPE-Send-Key

			extraAttributes.push([
				'Vendor-Specific',
				311,
				[[17, encodeTunnelPW(keyingMaterial.slice(0, 64), packet.authenticator, secret)]],
			]); // MS-MPPE-Recv-Key
		} else {
			console.error(
				'FATAL: no exportKeyingMaterial method available!!!, you need latest NODE JS, see https://github.com/nodejs/node/pull/31814'
			);
		}
		return extraAttributes;
	}

	peapAuthResponse(
		identifier: number,
		success: boolean,
		socket: tls.TLSSocket,
		packet: IPacket
	): IPacketHandlerResult {
		const extraAttributes = this.peapExtraAttributes(socket, packet);
		return authResponse(identifier, success, packet, extraAttributes);
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
			const { data } = decodeEAPHeader(msg);
			let connection = this.openTLSSockets.get(stateID) as ITLSServer;

			// check if no data package is there and we have something in the queue, if so.. empty the queue first
			if (!data || data.length === 0) {
				const queuedData = this.queueData.get(stateID);
				if (queuedData instanceof Buffer && queuedData.length > 0) {
					log(`returning queued data for ${stateID}`);
					return this.buildEAPPEAPResponse(
						identifier,
						EAPMessageType.PEAP,
						0x00,
						stateID,
						queuedData,
						false
					);
				}

				// log(`empty data queue for ${stateID}`);
				// return {};
			}

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
						this.peapAuthResponse(
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
					this.buildEAPPEAPResponse(
						identifier,
						EAPMessageType.PEAP,
						0x00,
						stateID,
						encryptedResponseData
					)
				);
			};

			const checkExistingSession = (isSessionReused) => {
				if (isSessionReused) {
					log('secured, session reused, accept auth!');
					sendResponsePromise.resolve(
						this.peapAuthResponse(identifier, true, connection.tls, packet)
					);
				}
			};

			// register event listeners
			connection.events.on('incoming', incomingMessageHandler);
			connection.events.on('response', responseHandler);
			connection.events.on('secured', checkExistingSession);

			if (!data || data.length === 0) {
				const challenge = crypto.randomBytes(16);
				const challengeData = Buffer.from([11, 16, challenge]);
				const plaintext = encodeTunnelPW(challengeData, packet.authenticator, secret);

				return this.buildEAPPEAPResponse(
					identifier,
					EAPMessageType.PEAP,
					0x20,
					stateID,
					plaintext
				);
			}

			connection.events.emit('decrypt', data);
			const responseData = await sendResponsePromise.promise;

			// cleanup
			connection.events.off('incoming', incomingMessageHandler);
			connection.events.off('response', responseHandler);
			connection.events.off('secured', checkExistingSession);

			// send response
			return responseData;
		} catch (err) {
			console.error('decoding of EAP-PEAP package failed', msg, err);
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
      for a PEAP server, this would imply returning EAP-Failure, for a
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
