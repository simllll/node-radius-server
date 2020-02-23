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

	// GoogleLDAPAuth (optimized for google auth)
	authentication: 'GoogleLDAPAuth',
	authenticationOptions: {
		base: 'dc=hokify,dc=com',
		tlsOptions: {
			key: fs.readFileSync('ldap.gsuite.hokify.com.40567.key'),
			cert: fs.readFileSync('ldap.gsuite.hokify.com.40567.crt')
		}
	}

	/** LDAP AUTH 
	authentication: 'LDAPAuth',
	authenticationOptions: {
		url: 'ldaps://ldap.google.com',
		base: 'dc=hokify,dc=com',
		tlsOptions: {
			key: fs.readFileSync('ldap.gsuite.hokify.com.40567.key'),
			cert: fs.readFileSync('ldap.gsuite.hokify.com.40567.crt'),
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
