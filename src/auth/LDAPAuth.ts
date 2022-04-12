import * as LdapAuth from 'ldapauth-fork';
import * as fs from 'fs';
import { IAuthentication } from '../interfaces/Authentication.js';
import { IContextLogger, ILogger } from '../interfaces/Logger.js';

interface ILDAPAuthOptions {
	/** ldap url
	 * e.g. ldaps://ldap.google.com
	 */
	url: string;
	/** base DN
	 *  e.g. 'dc=hokify,dc=com', */
	base: string;

	tls: {
		keyFile: string;
		certFile: string;
	};
	/** tls options
	 * e.g. {
			servername: 'ldap.google.com'
		} */
	tlsOptions?: any;
	/**
	 * searchFilter
	 */
	searchFilter?: string;
}

export class LDAPAuth implements IAuthentication {
	private ldap: LdapAuth;

	private logger: IContextLogger;

	constructor(config: ILDAPAuthOptions, logger: ILogger) {
		const tlsOptions = {
			key: fs.readFileSync(config.tls.keyFile),
			cert: fs.readFileSync(config.tls.certFile),
			...config.tlsOptions,
		};
		this.logger = logger.context('LDAPAuth');

		this.ldap = new LdapAuth({
			url: config.url,
			searchBase: config.base,
			tlsOptions,
			searchFilter: config.searchFilter || '(uid={{username}})',
			reconnect: true,
		});
		this.ldap.on('error', (err) => {
			this.logger.error('LdapAuth: ', err);
		});
	}

	async authenticate(username: string, password: string): Promise<boolean> {
		const authResult: boolean = await new Promise((resolve, reject) => {
			this.ldap.authenticate(username, password, (err, user) => {
				if (err) {
					resolve(false);
					this.logger.error('ldap error', err);
					// reject(err);
				}
				if (user) resolve(user);
				else reject();
			});
		});

		return authResult;
	}
}
