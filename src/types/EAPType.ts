export interface IEAPType {
	handleMessage(msg: Buffer, state: string, handlers, identifier: number);
}
