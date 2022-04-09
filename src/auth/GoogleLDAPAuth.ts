import ldapjs, { ClientOptions } from 'ldapjs';
import tls from 'tls';
import fs from 'fs';
import { IAuthentication } from '../interfaces/Authentication';
import { ILogger } from '../interfaces/Logger';

const usernameFields = ['posixUid', 'mail'];

// TLS:
// https://github.com/ldapjs/node-ldapjs/issues/307

interface IGoogleLDAPAuthOptions {
	/** base DN
	 *  e.g. 'dc=hokify,dc=com', */
	base: string;
	searchBase?: string; // default ou=users,{{base}}
	tls: {
		keyFile: string;
		certFile: string;
	};
	/** tls options
	 * e.g. {
			key: fs.readFileSync('ldap.gsuite.key'),
			cert: fs.readFileSync('ldap.gsuite.crt')
		} */
	tlsOptions?: tls.TlsOptions;
}

export class GoogleLDAPAuth implements IAuthentication {
	private lastDNsFetch: Date;

	private allValidDNsCache: { [key: string]: string };

	private base: string;

	private config: ClientOptions;

	searchBase: string;

	constructor(config: IGoogleLDAPAuthOptions, private logger: ILogger) {
		this.base = config.base;
		this.searchBase = config.searchBase || `ou=users,${this.base}`;

		const tlsOptions = {
			key: fs.readFileSync(config.tls.keyFile),
			cert: fs.readFileSync(config.tls.certFile),
			servername: 'ldap.google.com',
			...config.tlsOptions,
		};

		this.config = {
			url: 'ldaps://ldap.google.com:636',
			tlsOptions,
		};

		this.fetchDNs().catch((err) => {
			this.logger.error('fatal error google ldap auth, cannot fetch DNs', err);
		});
	}

	private async fetchDNs() {
		const dns: { [key: string]: string } = {};

		await new Promise<void>((resolve, reject) => {
			const ldapDNClient = ldapjs.createClient(this.config).on('error', (error) => {
				this.logger.error('Error in ldap', error);
				reject(error);
			});

			ldapDNClient.search(
				this.searchBase,
				{
					scope: 'sub',
				},
				(err, res) => {
					if (err) {
						reject(err);
						return;
					}

					res.on('searchEntry', (entry) => {
						// this.logger.debug('entry: ' + JSON.stringify(entry.object));
						usernameFields.forEach((field) => {
							const index = entry.object[field] as string;
							dns[index] = entry.object.dn;
						});
					});

					res.on('searchReference', (referral) => {
						this.logger.debug(`referral: ${referral.uris.join()}`);
					});

					res.on('error', (ldapErr) => {
						this.logger.error(`error: ${JSON.stringify(ldapErr)}`);
						reject(ldapErr);
					});

					res.on('end', (result) => {
						console.log('this', this);
						this.logger.debug(`ldap status: ${result?.status}`);

						// replace with new dns
						this.allValidDNsCache = dns;
						// this.logger.debug('allValidDNsCache', this.allValidDNsCache);
						resolve();
					});
				}
			);
		});
		this.lastDNsFetch = new Date();
	}

	async authenticate(
		username: string,
		password: string,
		count = 0,
		forceFetching = false
	): Promise<boolean> {
		const cacheValidTime = new Date();
		cacheValidTime.setHours(cacheValidTime.getHours() - 12);

		/*
		 just a test for super slow google responses
		await new Promise((resolve, reject) => {
			setTimeout(resolve, 10000); // wait 10 seconds
		})
		 */

		let dnsFetched = false;

		if (!this.lastDNsFetch || this.lastDNsFetch < cacheValidTime || forceFetching) {
			this.logger.debug('fetching dns');
			await this.fetchDNs();
			dnsFetched = true;
		}

		if (count > 5) {
			throw new Error('Failed to authenticate with LDAP!');
		}
		// const dn = ;
		const dn = this.allValidDNsCache[username];
		if (!dn) {
			if (!dnsFetched && !forceFetching) {
				return this.authenticate(username, password, count, true);
			}
			// this.logger.this.logger.debug('this.allValidDNsCache', this.allValidDNsCache);
			this.logger.error(`invalid username, not found in DN: ${username}`); // , this.allValidDNsCache);
			return false;
		}

		const authResult: boolean = await new Promise((resolve, reject) => {
			// we never unbding a client, therefore create a new client every time
			const authClient = ldapjs.createClient(this.config);

			authClient.bind(dn, password, (err, res) => {
				if (err) {
					if (err && (err as any).stack && (err as any).stack.includes(`ldap.google.com closed`)) {
						count += 1;
						// wait 1 second to give the ldap error handler time to reconnect
						setTimeout(() => resolve(this.authenticate(dn, password)), 2000);
						return;
					}

					resolve(false);
					// this.logger.error('ldap error', err);
					// reject(err);
				}
				if (res) resolve(res);
				else reject();

				authClient.unbind();
			});
		});

		return authResult;
	}
}
