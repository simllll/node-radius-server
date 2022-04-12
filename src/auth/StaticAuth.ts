import { IAuthentication } from '../interfaces/Authentication.js';
import { IContextLogger, ILogger } from '../interfaces/Logger.js';

interface IStaticAuthOtions {
	validCredentials: {
		username: string;
		password: string;
	}[];
}

export class StaticAuth implements IAuthentication {
	private validCredentials: { username: string; password: string }[];
	private logger: IContextLogger;

	constructor(options: IStaticAuthOtions, logger: ILogger) {
		this.logger = logger.context('StaticAuth');
		this.validCredentials = options.validCredentials;
	}

	async authenticate(username: string, password: string) {
		return !!this.validCredentials.find(
			(credential) => credential.username === username && credential.password === password
		);
	}
}
