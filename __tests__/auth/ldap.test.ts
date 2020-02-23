import 'mocha';
import { expect } from 'chai';
import * as fs from 'fs';
import { LDAPAuth } from '../../src/auth/LDAPAuth';

describe('test ldap auth', function() {
	this.timeout(10000);
	it('authenticate against ldap server', async () => {
		const auth = new LDAPAuth({
			url: 'ldaps://ldap.google.com:636',
			base: 'dc=hokify,dc=com',
			tlsOptions: {
				servername: 'ldap.google.com',
				key: fs.readFileSync('./ldap.gsuite.hokify.com.40567.key'),
				cert: fs.readFileSync('./ldap.gsuite.hokify.com.40567.crt'),
			}
		});

		const result = await auth.authenticate('username', 'password');

		expect(result).to.equal(true);
	});
});
