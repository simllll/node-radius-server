import 'mocha';
import { expect } from 'chai';
import { IMAPAuth } from '../../src/auth/IMAPAuth';

describe('test imap auth', () => {
	it('authenticate against imap server', async () => {
		const auth = new IMAPAuth({
			host: 'imap.gmail.com',
			port: 993,
			useSecureTransport: true,
			validHosts: ['gmail.com'],
		});

		const result = await auth.authenticate('username', 'password');

		expect(result).to.equal(true);
	});
});
