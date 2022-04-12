import radius from 'radius';
import { EventEmitter } from 'events';
import { IPacketHandlerResult, PacketResponseCode } from '../interfaces/PacketHandler.js';

import { PacketHandler } from './PacketHandler.js';
import { UDPServer } from '../server/UDPServer.js';
import { startTLSServer } from '../tls/crypt.js';
import { RadiusServerOptions } from '../interfaces/RadiusServerOptions.js';
import { ConsoleLogger, LogLevel } from '../logger/ConsoleLogger.js';

function hasLogger(options): options is { logger: ConsoleLogger } {
	return !!options.logger;
}

function hasLogLevel(options): options is { logLevel?: LogLevel } {
	return options.logLevel !== undefined;
}

export class RadiusServer extends UDPServer {
	private packetHandler: PacketHandler;

	constructor(private options: RadiusServerOptions) {
		super(
			options.port || 1812,
			options.address || '0.0.0.0',
			(hasLogger(options) && options.logger) ||
				new ConsoleLogger((hasLogLevel(options) && options.logLevel) || LogLevel.Log)
		);
		this.packetHandler = new PacketHandler(
			options.authentication,
			options.tlsOptions,
			this.logger,
			options.secret,
			options.vlan
		);
		this.installListeners();
	}

	public override async start(): Promise<EventEmitter> {
		// test node version
		const testSocket = startTLSServer(this.options.tlsOptions, this.logger);
		if (typeof testSocket.tls.exportKeyingMaterial !== 'function') {
			this.logger.error(`UNSUPPORTED NODE VERSION (${process.version}) FOUND!!`);
			this.logger.log('min version supported is node js 14. run "sudo npx n 14"');
			process.exit(-1);
		}
		return super.start();
	}

	private installListeners(): void {
		super.on('message', async (msg, rinfo) => {
			try {
				const response = await this.handleMessage(msg);

				if (response) {
					super.sendToClient(
						response.data,
						rinfo.port,
						rinfo.address,
						(err, _bytes) => {
							if (err) {
								this.logger.log('Error sending response to ', rinfo);
							}
						},
						response.expectAcknowledgment
					);
				}
			} catch (err) {
				this.logger.error('err', err);
			}
		});
	}

	async handleMessage(
		msg: Buffer
	): Promise<{ data: Buffer; expectAcknowledgment?: boolean } | undefined> {
		const packet = radius.decode({ packet: msg, secret: this.options.secret });

		if (packet.code !== 'Access-Request') {
			this.logger.error('unknown packet type: ', packet.code);
			return undefined;
		}

		const response: IPacketHandlerResult = await this.packetHandler.handlePacket(packet);

		// still no response, we are done here
		if (!response || !response.code) {
			return undefined;
		}

		// all fine, return radius encoded response
		return {
			data: radius.encode_response({
				packet,
				code: response.code,
				secret: this.options.secret,
				attributes: response.attributes,
			}),
			// if message is accept or reject, we conside this as final message
			// this means we do not expect a reponse from the client again (acknowledgement for package)
			expectAcknowledgment: response.code === PacketResponseCode.AccessChallenge,
		};
	}
}
