/* eslint-disable @typescript-eslint/no-var-requires */
const fs = require('fs');
const path = require('path');

const SSL_CERT_DIRECTORY = path.join(__dirname, './ssl/cert');

module.exports = {
	port: 1812,
	// radius secret
	secret: 'testing123',

	certificate: {
		ca: fs.readFileSync(path.join(SSL_CERT_DIRECTORY, '/ca.pem'), 'utf8'),
		cert: fs.readFileSync(path.join(SSL_CERT_DIRECTORY, '/server.crt'), 'utf8'),
		key: [
			{
				pem: fs.readFileSync(path.join(SSL_CERT_DIRECTORY, '/server.key'), 'utf8'),
				passphrase: 'whatever',
			},
		],
		// sessionTimeout: 3600,
		// sesionIdContext: 'meiasdfkljasdft!',
		// ticketKeys: Buffer.from('123456789012345678901234567890123456789012345678'),
	},

	// StaticAuth
	authentication: 'StaticAuth',
	authenticationOptions: {
		validCredentials: [
			{
				username: 'testing',
				password: 'password',
			},
			{
				username: 't',
				password: 'p',
			},
			{
				username: 'user',
				password: 'pwd',
			},
		],
	},

	/* GoogleLDAPAuth (optimized for google auth)
	authentication: 'GoogleLDAPAuth',
	authenticationOptions: {
		base: 'dc=hokify,dc=com',
		// get your keys from http://admin.google.com/ -> Apps -> LDAP -> Client
		tls: {
			keyFile: 'ldap.gsuite.key',
			certFile: 'ldap.gsuite.crt',
		},
	},
	*/

	/** LDAP AUTH
	authentication: 'LDAPAuth',
	authenticationOptions: {
		url: 'ldaps://ldap.google.com',
		base: 'dc=hokify,dc=com',
		tls: {
			keyFile: 'ldap.gsuite.key',
			certFile: 'ldap.gsuite.crt'
		},
		tlsOptions: {
			servername: 'ldap.google.com'
		}
	}
	*/

	/** IMAP AUTH
	authentication: 'IMAPAuth',
	authenticationOptions: {
		host: 'imap.gmail.com',
		port: 993,
		useSecureTransport: true,
		validHosts: ['hokify.com']
	}
	 */

	/** SMTP AUTH
	authentication: 'IMAPAuth',
	authenticationOptions: {
		host: 'smtp.gmail.com',
		port: 465,
		useSecureTransport: true,
		validHosts: ['gmail.com']
	}
	 */
};
