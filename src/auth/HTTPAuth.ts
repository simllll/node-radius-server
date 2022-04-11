import fetch from 'node-fetch';
import { IAuthentication } from '../interfaces/Authentication.js';
import { ILogger } from '../interfaces/Logger.js';

interface IHTTPAuthOptions {
	url: string;
}

export class HTTPAuth implements IAuthentication {
	private url: string;

	constructor(config: IHTTPAuthOptions, private logger: ILogger) {
		this.url = config.url;
	}

	async authenticate(username: string, password: string) {
		const result = await fetch(this.url, {
			method: 'post',
			body: JSON.stringify({
				username,
				password,
			}),
			headers: { 'Content-Type': 'application/json' },
		});

		if (result.status === 200) {
			return true;
		}

		this.logger.log(`HTTP authentication failed, response code: ${result.status}`);

		return false;
	}
}
