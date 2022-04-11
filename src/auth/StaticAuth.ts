import { IAuthentication } from '../interfaces/Authentication.js';
import { ILogger } from '../interfaces/Logger.js';

interface IStaticAuthOtions {
	validCredentials: {
		username: string;
		password: string;
	}[];
}

export class StaticAuth implements IAuthentication {
	private validCredentials: { username: string; password: string }[];

	constructor(options: IStaticAuthOtions, private logger: ILogger) {
		this.validCredentials = options.validCredentials;
	}

	async authenticate(username: string, password: string) {
		return !!this.validCredentials.find(
			(credential) => credential.username === username && credential.password === password
		);
	}
}
