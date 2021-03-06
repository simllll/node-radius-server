import * as imaps from 'imap-simple';
import { IAuthentication } from '../types/Authentication';

interface IIMAPAuthOptions {
	host: string;
	port?: number;
	useSecureTransport?: boolean;
	validHosts?: string[];
}

export class IMAPAuth implements IAuthentication {
	private host: string;

	private port = 143;

	private useSecureTransport = false;

	private validHosts?: string[];

	constructor(config: IIMAPAuthOptions) {
		this.host = config.host;
		if (config.port !== undefined) {
			this.port = config.port;
		}
		if (config.useSecureTransport !== undefined) {
			this.useSecureTransport = config.useSecureTransport;
		}
		if (config.validHosts !== undefined) {
			this.validHosts = config.validHosts;
		}
	}

	async authenticate(username: string, password: string) {
		if (this.validHosts) {
			const domain = username.split('@').pop();
			if (!domain || !this.validHosts.includes(domain)) {
				console.info('invalid or no domain in username', username, domain);
				return false;
			}
		}
		let success = false;
		try {
			const connection = await imaps.connect({
				imap: {
					host: this.host,
					port: this.port,
					tls: this.useSecureTransport,
					user: username,
					password,
					tlsOptions: {
						servername: this.host, // SNI (needs to be set for gmail)
					},
				},
			});

			success = true;

			connection.end();
		} catch (err) {
			console.error('imap auth failed', err);
		}
		return success;
	}
}
