import * as dgram from 'dgram';
import * as radius from 'radius';
// import * as dgram from "dgram";
// import * as fs from 'fs';
import { EAPHandler } from './eap';
import { makeid } from './helpers';

import { LDAPAuth } from './ldap';
import { AdditionalAuthHandler } from './types/Handler';

const server = dgram.createSocket('udp4');

// not used right now, using stunnel to connect to ldap
/* const tlsOptions = {
	key: fs.readFileSync('ldap.gsuite.hokify.com.40567.key'),
	cert: fs.readFileSync('ldap.gsuite.hokify.com.40567.crt'),

	// This is necessary only if using the client certificate authentication.
	requestCert: true,

	// This is necessary only if the client uses the self-signed certificate.
	ca: [fs.readFileSync('ldap.gsuite.hokify.com.40567.key')]
}; */

const { argv } = require('yargs')
	.usage('Simple Google LDAP <> RADIUS Server\nUsage: $0')
	.example('$0 --port 1812 -s radiussecret')
	.default({
		port: 1812,
		s: 'testing123',
		baseDN: 'dc=hokify,dc=com',
		ldapServer: 'ldap://127.0.0.1:1636'
	})
	.describe('baseDN', 'LDAP Base DN')
	.describe('ldapServer', 'LDAP Server')
	.describe('port', 'RADIUS server listener port')
	.alias('s', 'secret')
	.describe('secret', 'RADIUS secret')
	.string(['secret', 'baseDN'])
	.demand('secret');

console.log(`Listener Port: ${argv.port}`);
console.log(`RADIUS Secret: ${argv.secret}`);
console.log(`LDAP Base DN: ${argv.baseDN}`);
console.log(`LDAP Server: ${argv.ldapServer}`);

// const ldap = new LDAPAuth({url: 'ldap://ldap.google.com', base: 'dc=hokify,dc=com', uid: 'uid', tlsOptions});

const ldap = new LDAPAuth(argv.ldapServer, argv.baseDN);

const eapHandler = new EAPHandler();

server.on('message', async function(msg, rinfo) {
	const packet = radius.decode({ packet: msg, secret: argv.secret });

	if (packet.code !== 'Access-Request') {
		console.log('unknown packet type: ', packet.code);
		return;
	}

	// console.log('packet.attributes', packet.attributes);

	// console.log('rinfo', rinfo);

	async function checkAuth(
		username: string,
		password: string,
		additionalAuthHandler?: AdditionalAuthHandler
	) {
		console.log(`Access-Request for ${username}`);
		let success = false;
		try {
			await ldap.authenticate(username, password);
			success = true;
		} catch (err) {
			console.error(err);
		}

		const attributes: any[] = [];

		if (additionalAuthHandler) {
			await additionalAuthHandler(success, { packet, attributes, secret: argv.secret });
		}

		const response = radius.encode_response({
			packet,
			code: success ? 'Access-Accept' : 'Access-Reject',
			secret: argv.secret,
			attributes
		});
		console.log(`Sending ${success ? 'accept' : 'reject'} for user ${username}`);

		server.send(response, 0, response.length, rinfo.port, rinfo.address, function(err, _bytes) {
			if (err) {
				console.log('Error sending response to ', rinfo);
			}
		});
	}

	if (packet.attributes['EAP-Message']) {
		const state = (packet.attributes.State && packet.attributes.State.toString()) || makeid(16);
		// EAP MESSAGE
		eapHandler.handleEAPMessage(packet.attributes['EAP-Message'], state, {
			response: (EAPMessage: Buffer) => {
				const attributes: any = [['State', Buffer.from(state)]];
				let sentDataSize = 0;
				do {
					if (EAPMessage.length > 0) {
						attributes.push(['EAP-Message', EAPMessage.slice(sentDataSize, sentDataSize + 253)]);
						sentDataSize += 253;
					}
				} while (sentDataSize < EAPMessage.length);

				const response = radius.encode_response({
					packet,
					code: 'Access-Challenge',
					secret: argv.secret,
					attributes
				});

				server.send(response, 0, response.length, rinfo.port, rinfo.address, function(err, _bytes) {
					if (err) {
						console.log('Error sending response to ', rinfo);
					}
				});
			},
			checkAuth
		});
	} else {
		const username = packet.attributes['User-Name'];
		const password = packet.attributes['User-Password'];

		checkAuth(username, password);
	}
});

server.on('listening', function() {
	const address = server.address();
	console.log(`radius server listening ${address.address}:${address.port}`);
});

server.bind(argv.port);
