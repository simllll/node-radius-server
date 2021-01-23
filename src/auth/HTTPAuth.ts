import axios from 'axios';
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
		let success = false;
		try {
			await axios
				.post(
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
				)
				.then((res) => {
					console.log(`Code: ${res.status}`);
					if (res.status === 200) {
						success = true;
						console.log('Return code 200, HTTP authentication successful');
					} else {
						console.log('HTTP authentication failed');
					}
				});
		} catch (err) {
			console.error('HTTP response error');
		}
		return success;
	}
}
