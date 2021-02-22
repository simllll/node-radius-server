export interface IAuthentication {
	authenticate(username: string, password: string): Promise<boolean>;
	authenticateMD5Challenge(
		identifier: number,
		username: string,
		challenge: Buffer,
		match: Buffer
	): Promise<boolean>;
}
