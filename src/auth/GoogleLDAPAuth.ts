import { ClientOptions, createClient } from 'ldapjs';
import debug from 'debug';
import * as tls from 'tls';
import * as fs from 'fs';
import { IAuthentication } from '../types/Authentication';

const usernameFields = ['posixUid', 'mail'];

const log = debug('radius:auth:google-ldap');
// TLS:
// https://github.com/ldapjs/node-ldapjs/issues/307

interface IGoogleLDAPAuthOptions {
	/** base DN
	 *  e.g. 'dc=hokify,dc=com', */
	base: string;
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

	constructor(config: IGoogleLDAPAuthOptions) {
		this.base = config.base;

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

		this.fetchDNs();
	}

	private async fetchDNs() {
		const dns: { [key: string]: string } = {};

		await new Promise((resolve, reject) => {
			const ldapDNClient = createClient(this.config).on('error', (error) => {
				console.error('Error in ldap', error);
				reject(error);
			});

			ldapDNClient.search(
				this.base,
				{
					scope: 'sub',
				},
				(err, res) => {
					if (err) {
						reject(err);
						return;
					}

					res.on('searchEntry', function (entry) {
						// log('entry: ' + JSON.stringify(entry.object));
						usernameFields.forEach((field) => {
							const index = entry.object[field] as string;
							dns[index] = entry.object.dn;
						});
					});

					res.on('searchReference', function (referral) {
						log(`referral: ${referral.uris.join()}`);
					});

					res.on('error', function (ldapErr) {
						console.error(`error: ${ldapErr.message}`);
						reject();
					});

					res.on('end', (result) => {
						log(`ldap status: ${result?.status}`);

						// replace with new dns
						this.allValidDNsCache = dns;
						// log('allValidDNsCache', this.allValidDNsCache);
						resolve();
					});
				}
			);
		});
		this.lastDNsFetch = new Date();
	}

	async authenticate(username: string, password: string, count = 0, forceFetching = false) {
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
			log('fetching dns');
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
			console.error(`invalid username, not found in DN: ${username}`); // , this.allValidDNsCache);
			return false;
		}

		const authResult: boolean = await new Promise((resolve, reject) => {
			// we never unbding a client, therefore create a new client every time
			const authClient = createClient(this.config);

			authClient.bind(dn, password, (err, res) => {
				if (err) {
					if (err && (err as any).stack && (err as any).stack.includes(`ldap.google.com closed`)) {
						count++;
						// wait 1 second to give the ldap error handler time to reconnect
						setTimeout(() => resolve(this.authenticate(dn, password)), 2000);
						return;
					}

					resolve(false);
					// console.error('ldap error', err);
					// reject(err);
				}
				if (res) resolve(res);
				else reject();

				authClient.unbind();
			});
		});

		return !!authResult;
	}
}
