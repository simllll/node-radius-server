export enum PacketResponseCode {
	AccessChallenge = 'Access-Challenge',
	AccessAccept = 'Access-Accept',
	AccessReject = 'Access-Reject'
}

export interface IPacketHandlerResult {
	code?: PacketResponseCode;
	attributes?: [string, Buffer | string][];
}

export interface IPacketAttributes {
	[key: string]: string | Buffer;
}

export interface IPacket {
	attributes: { [key: string]: string | Buffer };
	authenticator?: Buffer;
}

export interface IPacketHandler {
	/** handlingType is the attreibute ID of the currently processing type (e.g. TTLS, GTC, MD5,..) */
	handlePacket(packet: IPacket, handlingType?: number): Promise<IPacketHandlerResult>;
}
