import { RadiusPacket } from 'radius';

export enum PacketResponseCode {
	AccessChallenge = 'Access-Challenge',
	AccessAccept = 'Access-Accept',
	AccessReject = 'Access-Reject'
}

export interface IPacketHandlerResult {
	code?: PacketResponseCode;
	attributes?: [string, Buffer][];
}

export interface IPacketHandler {
	handlePacket(
		attributes: { [key: string]: Buffer },
		orgRadiusPacket: RadiusPacket
	): Promise<IPacketHandlerResult>;
}
