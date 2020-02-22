import { RadiusPacket } from 'radius';

export type ResponseHandler = (
	msg: Buffer
) => Promise<{ identifier: number; response: ResponseHandler }>;
export type ResponseAuthHandler = (
	username: string,
	password: string,
	additionalAuthHandler?: AdditionalAuthHandler
) => void;

export interface IResponseHandlers {
	response: ResponseHandler;
	checkAuth: ResponseAuthHandler;
}

export type AdditionalAuthHandler = (
	success: boolean,
	params: { packet: RadiusPacket; attributes: any[]; secret: string }
) => void;
