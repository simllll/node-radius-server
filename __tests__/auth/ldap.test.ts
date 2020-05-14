import 'mocha';
import { expect } from 'chai';
import { LDAPAuth } from '../../src/auth/LDAPAuth';

describe('test ldap auth', function () {
	this.timeout(10000);
	it('authenticate against ldap server', async () => {
		const auth = new LDAPAuth({
			url: 'ldaps://ldap.google.com:636',
			base: 'dc=hokify,dc=com',
			tls: {
				keyFile: './ldap.gsuite.key',
				certFile: './ldap.gsuite.crt',
			},
			tlsOptions: {
				servername: 'ldap.google.com',
			},
		});

		const result = await auth.authenticate('username', 'password');

		expect(result).to.equal(true);
	});
});
