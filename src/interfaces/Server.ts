import { RemoteInfo } from 'dgram';

/**
 * @fires IServer#message
 */
export interface IServer {
	/**
	 *
	 * @param msg
	 * @param port
	 * @param address
	 * @param callback
	 * @param expectAcknowledgment: if set to false, message is not retried to send again if there is no confirmation
	 */
	sendToClient(
		msg: string | Uint8Array,
		port?: number,
		address?: string,
		callback?: (error: Error | null, bytes: number) => void,
		expectAcknowledgment?: boolean
	): void;

	/**
	 * Message event.
	 *
	 * @event IServer#message
	 * @type {object}
	 * @property {message} data - the data of the incoming message
	 * @property {rinfo} optionally remote information
	 */
	on(event: 'message', listener: (msg: Buffer, rinfo?: RemoteInfo) => void): this;
}
