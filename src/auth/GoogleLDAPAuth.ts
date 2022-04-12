import ldapjs, { ClientOptions } from 'ldapjs';
import * as tls from 'tls';
import * as fs from 'fs';
import { IAuthentication } from '../interfaces/Authentication.js';
import { ILogger } from '../interfaces/Logger.js';

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
	private base: string;

	private config: ClientOptions;

	private searchBase: string;

	private dnsFetch: Promise<{ [key: string]: string }> | undefined;

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

		this.dnsFetch = this.fetchDNs();
		this.dnsFetch.catch((err) => {
			this.logger.error('fatal error google ldap auth, cannot fetch DNs', err);
		});
	}

	private async fetchDNs(): Promise<{ [key: string]: string }> {
		try {
			const dns: { [key: string]: string } = {};

			const dnResult = await new Promise<{ [key: string]: string }>((resolve, reject) => {
				const ldapDNClient = ldapjs.createClient(this.config).on('error', (error) => {
					this.logger.error('Error in ldap', error);
					reject(error);
				});

				ldapDNClient.search(
					this.searchBase,
					{
						scope: 'sub',
						// only select required attributes
						attributes: [...usernameFields, 'dn'],
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
							this.logger.debug(`ldap status: ${result?.status}`);

							// this.logger.debug('allValidDNsCache', this.allValidDNsCache);
							resolve(dns);
						});
					}
				);
			});
			setTimeout(() => {
				this.dnsFetch = undefined;
			}, 60 * 60 * 12 * 1000); // reset cache after 12h
			return dnResult;
		} catch (err) {
			console.error('dns fetch err', err);
			// retry dns fetch next time
			this.dnsFetch = undefined;
			throw err;
		}
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

		if (!this.dnsFetch || forceFetching) {
			this.logger.debug('fetching dns');
			this.dnsFetch = this.fetchDNs();
			dnsFetched = true;
		}
		const allValidDNsCache = await this.dnsFetch;

		if (count > 5) {
			throw new Error('Failed to authenticate with LDAP!');
		}
		// const dn = ;
		const dn = allValidDNsCache[username];
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
