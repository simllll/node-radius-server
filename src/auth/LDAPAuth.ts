import * as LdapAuth from 'ldapauth-fork';
import { IAuthentication } from '../types/Authentication';

interface ILDAPAuthOptions {
	/** ldap url
	 * e.g. ldaps://ldap.google.com
	 */
	url: string;
	/** base DN
	 *  e.g. 'dc=hokify,dc=com', */
	base: string;
	/** tls options
	 * e.g. {
			key: fs.readFileSync('ldap.gsuite.hokify.com.40567.key'),
			cert: fs.readFileSync('ldap.gsuite.hokify.com.40567.crt'),
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

	constructor(options: ILDAPAuthOptions) {
		this.ldap = new LdapAuth({
			url: options.url,
			searchBase: options.base,
			tlsOptions: options.tlsOptions,
			searchFilter: options.searchFilter || '(uid={{username}})',
			reconnect: true
		});
		this.ldap.on('error', function(err) {
			console.error('LdapAuth: ', err);
		});
	}

	async authenticate(username: string, password: string) {
		// console.log('AUTH', this.ldap);
		const authResult: boolean = await new Promise((resolve, reject) => {
			this.ldap.authenticate(username, password, function(err, user) {
				if (err) {
					resolve(false);
					console.error('ldap error', err);
					// reject(err);
				}
				if (user) resolve(user);
				else reject();
			});
		});

		return !!authResult;
	}
}
