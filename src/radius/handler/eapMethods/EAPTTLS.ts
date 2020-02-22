/* eslint-disable no-bitwise */
import * as tls from 'tls';
import * as NodeCache from 'node-cache';
import { RadiusPacket } from 'radius';
import { encodeTunnelPW, ITLSServer, startTLSServer } from '../../../tls/crypt';
import { ResponseAuthHandler } from '../../../types/Handler';
import { PAPChallenge } from './challenges/PAPChallenge';
import { IPacketHandlerResult, PacketResponseCode } from '../../../types/PacketHandler';
import { MAX_RADIUS_ATTRIBUTE_SIZE, newDeferredPromise } from '../../../helpers';
import { IEAPMethod } from '../../../types/EAPMethod';
import { IAuthentication } from '../../../types/Authentication';
import { secret } from '../../../../config';

interface IEAPResponseHandlers {
	response: (respData?: Buffer, msgType?: number) => void;
	checkAuth: ResponseAuthHandler;
}

/*	const handlers = {
	response: (EAPMessage: Buffer) => {
		const attributes: any = [['State', Buffer.from(state)]];
		let sentDataSize = 0;
		do {
			if (EAPMessage.length > 0) {
				attributes.push([
					'EAP-Message',
					EAPMessage.slice(sentDataSize, sentDataSize + MAX_RADIUS_ATTRIBUTE_SIZE)
				]);
				sentDataSize += MAX_RADIUS_ATTRIBUTE_SIZE;
			}
		} while (sentDataSize < EAPMessage.length);

		const response = radius.encode_response({
			packet,
			code: 'Access-Challenge',
			secret: this.secret,
			attributes
		});

		waitForNextMsg[state] = newDeferredPromise();

		server.sendToClient(
			response,
			rinfo.port,
			rinfo.address,
			function(err, _bytes) {
				if (err) {
					console.log('Error sending response to ', rinfo);
				}
			},
			state
		);

		return waitForNextMsg[state].promise;
	},
	checkAuth
};


const attributes: any = [['State', Buffer.from(stateID)]];
let sentDataSize = 0;
do {
	if (EAPMessage.length > 0) {
		attributes.push([
			'EAP-Message',
			EAPMessage.slice(sentDataSize, sentDataSize + MAX_RADIUS_ATTRIBUTE_SIZE)
		]);
		sentDataSize += MAX_RADIUS_ATTRIBUTE_SIZE;
	}
} while (sentDataSize < EAPMessage.length);

const response = radius.encode_response({
	packet,
	code: 'Access-Challenge',
	secret: this.secret,
	attributes
});

waitForNextMsg[stateID] = newDeferredPromise();

server.sendToClient(
	response,
	rinfo.port,
	rinfo.address,
	function(err, _bytes) {
		if (err) {
			console.log('Error sending response to ', rinfo);
		}
	},
	stateID
);

return waitForNextMsg[stateID].promise;
*/
/* if (waitForNextMsg[state]) {
	const identifier = attributes['EAP-Message'].slice(1, 2).readUInt8(0); // .toString('hex');
	waitForNextMsg[state].resolve({ response: handlers.response, identifier });
} */

function tlsHasExportKeyingMaterial(
	tlsSocket: any
): tlsSocket is {
	exportKeyingMaterial: (length: number, label: string, context?: Buffer) => Buffer;
} {
	return typeof (tlsSocket as any).exportKeyingMaterial === 'function';
}

export class EAPTTLS implements IEAPMethod {
	private papChallenge: PAPChallenge = new PAPChallenge();

	// { [key: string]: Buffer } = {};
	private queueData = new NodeCache({ useClones: false, stdTTL: 60 }); // queue data maximum for 60 seconds

	private openTLSSockets = new NodeCache({ useClones: false, stdTTL: 3600 }); // keep sockets for about one hour

	getEAPType(): number {
		return 21;
	}

	identify(identifier: number, stateID: string): IPacketHandlerResult {
		return this.buildEAPTTLSResponse(identifier, 21, 0x20, stateID);
	}

	constructor(private authentication: IAuthentication) {}

	private buildEAPTTLSResponse(
		identifier: number,
		msgType = 21,
		msgFlags = 0x00,
		stateID: string,
		data?: Buffer,
		newResponse = true
	): IPacketHandlerResult {
		const maxSize = (MAX_RADIUS_ATTRIBUTE_SIZE - 5) * 4;
		console.log('maxSize', maxSize);

		/* it's the first one and we have more, therefore include length */
		const includeLength = data && newResponse && data.length > maxSize;

		// extract data party
		const dataToSend = data && data.length > 0 && data.slice(0, maxSize);
		const dataToQueue = data && data.length > maxSize && data.slice(maxSize);

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
			flags // flags: 000000 (L include lenghts, M .. more to come)
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

		console.log('<<<<<<<<<<<< EAP RESPONSE TO CLIENT', {
			code: 1,
			identifier: identifier + 1,
			includeLength,
			dataLength: (data && data.byteLength) || 0,
			msgType: msgType.toString(10),
			flags: `00000000${flags.toString(2)}`.substr(-8),
			data
		});

		if (dataToQueue) {
			// we couldn't send all at once, queue the rest and send later
			this.queueData.set(stateID, dataToQueue);
		} else {
			this.queueData.del(stateID);
		}

		const attributes: any = [['State', Buffer.from(stateID)]];
		let sentDataSize = 0;
		do {
			if (resBuffer.length > 0) {
				attributes.push([
					'EAP-Message',
					resBuffer.slice(sentDataSize, sentDataSize + MAX_RADIUS_ATTRIBUTE_SIZE)
				]);
				sentDataSize += MAX_RADIUS_ATTRIBUTE_SIZE;
			}
		} while (sentDataSize < resBuffer.length);

		return {
			code: PacketResponseCode.AccessChallenge,
			attributes
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
			lengthIncluded: flags & 0b010000000,
			// M
			moreFragments: flags & 0b001000000,
			// S
			start: flags & 0b000100000,
			// R
			// reserved: flags & 0b000011000,
			// V
			version: flags & 0b010000111
		};

		let msglength;
		if (decodedFlags.lengthIncluded) {
			msglength = msg.slice(6, 10).readInt32BE(0); // .readDoubleLE(0); // .toString('hex');
		}
		const data = msg.slice(decodedFlags.lengthIncluded ? 10 : 6, msg.length);

		return {
			decodedFlags,
			msglength,
			data
		};
	}

	authResponse(
		identifier: number,
		success: boolean,
		socket: tls.TLSSocket,
		packet: RadiusPacket
	): IPacketHandlerResult {
		const buffer = Buffer.from([
			success ? 3 : 4, // 3.. success, 4... failure
			identifier + 1,
			0, // length (1/2)
			4 //  length (2/2)
		]);

		const attributes: any[] = [];
		attributes.push(['EAP-Message', buffer]);

		if (packet.attributes && packet.attributes['User-Name']) {
			// reappend username to response
			attributes.push(['User-Name', packet.attributes['User-Name']]);
		}

		/*
					if (sess->eap_if->eapKeyDataLen > 64) {
												len = 32;
								} else {
												len = sess->eap_if->eapKeyDataLen / 2;
								}
					 */
		if (tlsHasExportKeyingMaterial(socket)) {
			const keyingMaterial = (socket as any).exportKeyingMaterial(128, 'ttls keying material');

			// console.log('keyingMaterial', keyingMaterial);

			// eapKeyData + len
			attributes.push([
				'Vendor-Specific',
				311,
				[
					[
						16,
						encodeTunnelPW(
							keyingMaterial.slice(64),
							(packet as any).authenticator,
							// params.packet.attributes['Message-Authenticator'],
							secret
						)
					]
				]
			]); //  MS-MPPE-Send-Key

			// eapKeyData
			attributes.push([
				'Vendor-Specific',
				311,
				[
					[
						17,
						encodeTunnelPW(
							keyingMaterial.slice(0, 64),
							(packet as any).authenticator,
							// params.packet.attributes['Message-Authenticator'],
							secret
						)
					]
				]
			]); // MS-MPPE-Recv-Key
		} else {
			console.error(
				'FATAL: no exportKeyingMaterial method available!!!, you need latest NODE JS, see https://github.com/nodejs/node/pull/31814'
			);
		}

		return {
			code: success ? PacketResponseCode.AccessAccept : PacketResponseCode.AccessReject,
			attributes
		};
	}

	async handleMessage(
		identifier: number,
		stateID: string,
		msg: Buffer,
		orgRadiusPacket: RadiusPacket
	): Promise<IPacketHandlerResult> {
		const { decodedFlags, msglength, data } = this.decodeTTLSMessage(msg);

		// check if no data package is there and we have something in the queue, if so.. empty the queue first
		if (!data || data.length === 0) {
			console.warn(
				`>>>>>>>>>>>> REQUEST FROM CLIENT: EAP TTLS, ACK / NACK (no data, just a confirmation, ID: ${identifier})`
			);
			const queuedData = this.queueData.get(stateID);
			if (queuedData instanceof Buffer && queuedData.length > 0) {
				return this.buildEAPTTLSResponse(identifier, 21, 0x00, stateID, queuedData, false);
			}

			return {};
		}

		console.log('>>>>>>>>>>>> REQUEST FROM CLIENT: EAP TTLS', {
			// flags: `00000000${flags.toString(2)}`.substr(-8),
			decodedFlags,
			identifier,
			msglength
			// data,
			// dataStr: data.toString()
		});

		let connection = this.openTLSSockets.get(stateID) as ITLSServer;

		if (!connection) {
			connection = startTLSServer();
			this.openTLSSockets.set(stateID, connection);

			connection.events.on('end', () => {
				// cleanup socket
				console.log('ENDING SOCKET');
				this.openTLSSockets.del(stateID);
			});
		}

		const sendResponsePromise = newDeferredPromise();

		const incomingMessageHandler = async (incomingData: Buffer) => {
			const type = incomingData.slice(3, 4).readUInt8(0);
			// const code = data.slice(4, 5).readUInt8(0);

			switch (type) {
				case 1: // PAP / CHAP
					try {
						const { username, password } = this.papChallenge.decode(incomingData);
						const authResult = await this.authentication.authenticate(username, password);

						sendResponsePromise.resolve(
							this.authResponse(identifier, authResult, connection.tls, orgRadiusPacket)
						);
					} catch (err) {
						// pwd not found..
						console.error('pwd not found', err);
						connection.events.emit('end');
						// NAK
						sendResponsePromise.resolve(this.buildEAPTTLSResponse(identifier, 3, 0, stateID));
					}
					break;
				default:
					console.log('data', incomingData);
					console.log('data str', incomingData.toString());

					// currentConnection!.events.emit('end');

					console.log('UNSUPPORTED AUTH TYPE, requesting PAP');
					// throw new Error(`unsupported auth type${type}`);
					sendResponsePromise.resolve(
						this.buildEAPTTLSResponse(identifier, 3, 0, stateID, Buffer.from([1]))
					);
			}
		};

		const responseHandler = (encryptedResponseData: Buffer) => {
			// send back...
			sendResponsePromise.resolve(
				this.buildEAPTTLSResponse(identifier, 21, 0x00, stateID, encryptedResponseData)
			);
		};

		// register event listeners
		connection.events.on('incoming', incomingMessageHandler);
		connection.events.on('response', responseHandler);

		// emit data to tls server
		connection.events.emit('send', data);
		const responseData = await sendResponsePromise.promise;

		// cleanup
		connection.events.off('incoming', incomingMessageHandler);
		connection.events.off('response', responseHandler);

		// send response
		return responseData; // this.buildEAPTTLSResponse(identifier, 21, 0x00, stateID, encryptedResponseData);
	}
}
