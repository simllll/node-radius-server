export interface IEAPChallenge {
	decode(data: Buffer, stateID: string): { username: string; password?: string };
}
