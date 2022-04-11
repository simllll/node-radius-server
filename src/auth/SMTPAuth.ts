import { SMTPClient } from 'smtp-client';
import { IAuthentication } from '../interfaces/Authentication.js';
import { ILogger } from '../interfaces/Logger.js';

interface ISMTPAuthOptions {
	host: string;
	port?: number;
	useSecureTransport?: boolean;
	validHosts?: string[];
}

export class SMTPAuth implements IAuthentication {
	private host: string;

	private port = 25;

	private useSecureTransport = false;

	private validHosts?: string[];

	constructor(options: ISMTPAuthOptions, private logger: ILogger) {
		this.host = options.host;

		if (options.port !== undefined) {
			this.port = options.port;
		}

		if (options.useSecureTransport !== undefined) {
			this.useSecureTransport = options.useSecureTransport;
		}

		if (options.validHosts !== undefined) {
			this.validHosts = options.validHosts;
		}
	}

	async authenticate(username: string, password: string) {
		if (this.validHosts) {
			const domain = username.split('@').pop();
			if (!domain || !this.validHosts.includes(domain)) {
				this.logger.log('invalid or no domain in username', username, domain);
				return false;
			}
		}

		const s = new SMTPClient({
			host: this.host,
			port: this.port,
			secure: this.useSecureTransport,
			tlsOptions: {
				servername: this.host, // SNI (needs to be set for gmail)
			},
		} as any); // secure is currently not part of type def..but it is available: https://www.npmjs.com/package/smtp-client

		let success = false;
		try {
			await s.connect();
			await s.greet({ hostname: 'mx.domain.com' }); // runs EHLO command or HELO as a fallback
			await s.authPlain({ username, password }); // authenticates a user

			success = true;

			s.close(); // runs QUIT command
		} catch (err) {
			this.logger.error('imap auth failed', err);
		}
		return success;
	}
}
