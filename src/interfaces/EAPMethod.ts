import { IPacket, IPacketHandlerResult } from './PacketHandler';

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
