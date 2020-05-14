import 'mocha';
import { expect } from 'chai';
import { GoogleLDAPAuth } from '../../src/auth/GoogleLDAPAuth';

describe('test google ldap auth', function () {
	this.timeout(10000);
	it('authenticate against ldap server', async () => {
		const auth = new GoogleLDAPAuth({
			base: 'dc=hokify,dc=com',
			tls: {
				keyFile: './ldap.gsuite.key',
				certFile: './ldap.gsuite.crt',
			},
		});

		const result = await auth.authenticate('username', 'password');

		expect(result).to.equal(true);
	});
});
