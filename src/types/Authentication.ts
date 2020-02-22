export interface IAuthentication {
	authenticate(username: string, password: string): Promise<boolean>;
}
