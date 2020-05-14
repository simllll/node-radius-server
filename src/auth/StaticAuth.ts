import { IAuthentication } from '../types/Authentication';

interface IStaticAuthOtions {
	validCrentials: {
		username: string;
		password: string;
	}[];
}

export class StaticAuth implements IAuthentication {
	private validCredentials: { username: string; password: string }[];

	constructor(options: IStaticAuthOtions) {
		this.validCredentials = options.validCrentials;
	}

	async authenticate(username: string, password: string) {
		return !!this.validCredentials.find(
			(credential) => credential.username === username && credential.password === password
		);
	}
}
