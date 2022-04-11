import { IPacket, IPacketHandlerResult } from './PacketHandler.js';

export enum EAPRequestType {
	REQUEST = 1,
	RESPONSE = 2,
	SUCCESS = 3,
	FAILURE = 4,
}

export enum EAPMessageType {
	IDENTIFY = 1,
	NOTIFICATION = 2,
	NAK = 3,
	MD5 = 4,
	GTC = 6,
	TTLS = 21,
	PEAP = 25,
	EXPANDED = 254,
}

export interface IEAPMethod {
	getEAPType(): number;

	identify(identifier: number, stateID: string, msg?: Buffer): IPacketHandlerResult;

	handleMessage(
		identifier: number,
		stateID: string,
		msg: Buffer,
		packet?: IPacket,
		identity?: string
	): Promise<IPacketHandlerResult>;
}
