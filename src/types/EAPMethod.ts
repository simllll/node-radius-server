import { RadiusPacket } from 'radius';
import { IPacketHandlerResult } from './PacketHandler';

export interface IEAPMethod {
	getEAPType(): number;

	identify(identifier: number, stateID: string): IPacketHandlerResult;

	handleMessage(
		identifier: number,
		stateID: string,
		msg: Buffer,
		orgRadiusPacket?: RadiusPacket
	): Promise<IPacketHandlerResult>;
}
