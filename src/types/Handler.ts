export type ResponseHandler = (msg: Buffer) => void;
export type ResponseAuthHandler = (username: string, password: string, identifier: number) => void;

export interface IResponseHandlers {
	response: ResponseHandler;
	checkAuth: ResponseAuthHandler;
}
