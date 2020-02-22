/* eslint-disable @typescript-eslint/no-var-requires */
const fs = require('fs');
const path = require('path');

const SSL_CERT_DIRECTORY = './ssl/cert';

module.exports = {
	port: 1812,
	// radius secret
	secret: 'testing123',

	certificate: {
		cert: fs.readFileSync(path.join(SSL_CERT_DIRECTORY, '/server.crt')),
		key: [
			{
				pem: fs.readFileSync(path.join(SSL_CERT_DIRECTORY, '/server.key')),
				passphrase: 'whatever2020'
			}
		]
	},

	// authentication
	authentication: 'ldap',
	authenticationOptions: {
		url: 'ldap://127.0.0.1:1636',
		base: 'dc=hokify,dc=com',
		tlsOptions2: {
			key: fs.readFileSync('ldap.gsuite.hokify.com.40567.key'),
			cert: fs.readFileSync('ldap.gsuite.hokify.com.40567.crt'),

			// This is necessary only if using the client certificate authentication.
			requestCert: true,

			// This is necessary only if the client uses the self-signed certificate.
			ca: [fs.readFileSync('ldap.gsuite.hokify.com.40567.key')]
		}
	}
};
