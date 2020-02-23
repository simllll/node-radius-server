import * as NodeCache from 'node-cache';

import { Client, createClient } from 'ldapjs';
import debug from 'debug';
import { IAuthentication } from '../types/Authentication';

const usernameFields = ['posixUid', 'mail'];

const log = debug('radius:auth:ldap');
// TLS:
// https://github.com/ldapjs/node-ldapjs/issues/307

export class GoogleLDAPAuth implements IAuthentication {
	cache = new NodeCache();

	ldap: Client;

	lastDNsFetch: Date;

	allValidDNsCache: { [key: string]: string };

	constructor(private url: string, private base: string, tlsOptions?) {
		this.ldap = createClient({ url, tlsOptions }).on('error', error => {
			console.error('Error in ldap', error);
		});

		this.fetchDNs();
	}

	private async fetchDNs() {
		const dns: { [key: string]: string } = {};

		await new Promise((resolve, reject) => {
			this.ldap.search(
				this.base,
				{
					scope: 'sub'
				},
				(err, res) => {
					if (err) {
						reject(err);
						return;
					}

					res.on('searchEntry', function(entry) {
						// log('entry: ' + JSON.stringify(entry.object));
						usernameFields.forEach(field => {
							const index = entry.object[field] as string;
							dns[index] = entry.object.dn;
						});
					});

					res.on('searchReference', function(referral) {
						log(`referral: ${referral.uris.join()}`);
					});

					res.on('error', function(ldapErr) {
						console.error(`error: ${ldapErr.message}`);
						reject();
					});

					res.on('end', result => {
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
		const cacheKey = `usr:${username}|pwd:${password}`;
		const fromCache = this.cache.get(cacheKey);
		if (fromCache !== undefined) {
			return fromCache;
		}

		const cacheValidTime = new Date();
		cacheValidTime.setHours(cacheValidTime.getHours() - 12);

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
			console.error(`invalid username, not found in DN: ${username}`);
			return false;
		}

		const authResult: boolean = await new Promise((resolve, reject) => {
			this.ldap.bind(dn, password, (err, res) => {
				if (err) {
					if (err && (err as any).stack && (err as any).stack.includes(`${this.url} closed`)) {
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
			});
		});

		this.cache.set(cacheKey, authResult, 86400);

		return authResult;
	}
}
