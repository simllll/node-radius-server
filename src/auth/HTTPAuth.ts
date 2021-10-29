import haxios from 'haxios';
import { IAuthentication } from '../types/Authentication';

interface IHTTPAuthOptions {
	url: string;
}

export class HTTPAuth implements IAuthentication {
	private url: string;

	constructor(config: IHTTPAuthOptions) {
		this.url = config.url;
	}

	async authenticate(username: string, password: string) {
		const result = await haxios.post(
			this.url,
			{
				username,
				password,
			},
			{
				validateStatus(status) {
					return status >= 200 && status < 500;
				},
			}
		);

		if (result.status === 200) {
			return true;
		}

		console.log(`HTTP authentication failed, response code: ${result.status}`);

		return false;
	}
}
