export interface IAuthChallenge {
	decode(data: Buffer): { username: string; password: string };
}
