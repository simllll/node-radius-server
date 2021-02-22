import { IPacket, IPacketHandlerResult } from './PacketHandler';

export interface IBuildEAP {
	resBuffer: Buffer;
	dataToQueue: false | Buffer | undefined;
}

export interface IEAPHeaderFlags {
	lengthIncluded: boolean;
	moreFragments: boolean;
	start: boolean;
	version: number;
}

export interface IEAPHeader {
	code: number;
	identifier: number;
	length: number;
	msglength: number;
	type: number;
	data: Buffer;
	decodedFlags: IEAPHeaderFlags;
}

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
