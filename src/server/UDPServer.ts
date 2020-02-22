import * as dgram from 'dgram';
import { SocketType } from 'dgram';
import * as events from 'events';
import { EventEmitter } from 'events';
import { newDeferredPromise } from '../helpers';
import { IServer } from '../types/Server';

export class UDPServer extends events.EventEmitter implements IServer {
	static MAX_RETRIES = 3;

	private timeout: { [key: string]: NodeJS.Timeout } = {};

	private server: dgram.Socket;

	constructor(private port: number, type: SocketType = 'udp4') {
		super();
		this.server = dgram.createSocket(type);
	}

	sendToClient(
		msg: string | Uint8Array,
		port?: number,
		address?: string,
		callback?: (error: Error | null, bytes: number) => void,
		expectAcknowledgment = true
	): void {
		let retried = 0;

		const sendResponse = (): void => {
			if (retried > 0) {
				console.warn(
					`no confirmation of last message from ${address}:${port}, re-sending response... (bytes: ${msg.length}, try: ${retried}/${UDPServer.MAX_RETRIES})`
				);
			}

			// send message to client
			this.server.send(msg, 0, msg.length, port, address, callback);

			// retry up to MAX_RETRIES to send this message,
			// we automatically retry if there is no confirmation (=any incoming message from client)
			// if expectAcknowledgment (e.g. Access-Accept or Access-Reject) is set, we do not retry
			const identifierForRetry = `${address}:${port}`;
			if (expectAcknowledgment && retried < UDPServer.MAX_RETRIES) {
				this.timeout[identifierForRetry] = setTimeout(sendResponse, 600 * (retried + 1));
			}
			retried += 1;
		};

		sendResponse();
	}

	async start(): Promise<EventEmitter> {
		const startServer = newDeferredPromise();
		this.server.on('listening', () => {
			const address = this.server.address();
			console.log(`radius server listening ${address.address}:${address.port}`);

			this.setupListeners();
			startServer.resolve();
		});

		this.server.on('message', (_msg, rinfo) => {
			console.log('incoming message 2');

			// message retrieved, reset timeout handler
			const identifierForRetry = `${rinfo.address}:${rinfo.port}`;
			if (this.timeout[identifierForRetry]) {
				clearTimeout(this.timeout[identifierForRetry]);
			}
		});

		this.server.bind(this.port);

		return startServer.promise;
	}

	private setupListeners() {
		this.server.on('message', (message, rinfo) => this.emit('message', message, rinfo));
	}
}
