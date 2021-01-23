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
			  .post(this.url, {
			    username: username,
			    password: password
			  })
			  .then(res => {
				    console.log("Code: " + res.status)
				    if (res.status == 200) {
				    	success = true;
				    	console.log("Return code 200, authentication successful.");
				    }
			  });
		} catch (err) {
			console.error('HTTP auth failed');
		}
		return success;
	}
}
