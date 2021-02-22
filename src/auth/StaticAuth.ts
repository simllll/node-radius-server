import * as crypto from 'crypto';
import { IAuthentication } from '../types/Authentication';

interface IStaticAuthOtions {
	validCredentials: {
		username: string;
		password: string;
	}[];
}

export class StaticAuth implements IAuthentication {
	private validCredentials: { username: string; password: string }[];

	constructor(options: IStaticAuthOtions) {
		this.validCredentials = options.validCredentials;
	}

	async authenticate(username: string, password: string): Promise<boolean> {
		return !!this.validCredentials.find(
			(credential) => credential.username === username && credential.password === password
		);
	}

	async authenticateMD5Challenge(
		identifier: number,
		username: string,
		challenge: Buffer,
		match: Buffer
	): Promise<boolean> {
		const user = this.validCredentials.find((credential) => credential.username === username);

		if (!user) {
			return false;
		}

		// EAP-Message Id + User Password + the Challenge value
		const md5 = crypto.createHash('md5');
		md5.write(Buffer.from([identifier]));
		md5.write(Buffer.from(user.password));
		md5.write(challenge);

		return match.equals(Buffer.from(md5.digest('hex'), 'hex'));
	}
}
