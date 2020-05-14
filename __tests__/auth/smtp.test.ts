import 'mocha';
import { expect } from 'chai';
import { SMTPAuth } from '../../src/auth/SMTPAuth';

describe('test smtp auth', () => {
	it('authenticate against smtp server', async () => {
		const auth = new SMTPAuth({
			host: 'smtp.gmail.com',
			port: 465,
			useSecureTransport: true,
			validHosts: ['gmail.com'],
		});

		const result = await auth.authenticate('username', 'password');

		expect(result).to.equal(true);
	});
});
