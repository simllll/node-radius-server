export interface IEAPChallenge {
	decode(data: Buffer): { username: string; password: string };
}
