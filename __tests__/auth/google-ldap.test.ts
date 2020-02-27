import 'mocha';
import { expect } from 'chai';
import * as fs from 'fs';
import { GoogleLDAPAuth } from '../../src/auth/GoogleLDAPAuth';

describe('test google ldap auth', function() {
	this.timeout(10000);
	it('authenticate against ldap server', async () => {
		const auth = new GoogleLDAPAuth({
			base: 'dc=hokify,dc=com',
			tlsOptions: {
				key: fs.readFileSync('./ldap.gsuite.key'),
				cert: fs.readFileSync('./ldap.gsuite.crt')
			}
		});

		const result = await auth.authenticate('username', 'password');

		expect(result).to.equal(true);
	});
});
