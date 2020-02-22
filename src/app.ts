import * as dgram from 'dgram';
import * as radius from 'radius';
// import * as dgram from "dgram";
// import * as fs from 'fs';
import { EAPHandler } from './eap';
import { IDeferredPromise, makeid, MAX_RADIUS_ATTRIBUTE_SIZE, newDeferredPromise } from './helpers';

import { GoogleLDAPAuth } from './auth/google-ldap';
import { AdditionalAuthHandler } from './types/Handler';

const server = dgram.createSocket('udp4');

const { argv } = require('yargs')
	.usage('RADIUS Server\nUsage: $0')
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

const ldap = new GoogleLDAPAuth(argv.ldapServer, argv.baseDN);

const eapHandler = new EAPHandler();
const timeout: { [key: string]: NodeJS.Timeout } = {};
const waitForNextMsg: { [key: string]: IDeferredPromise } = {};

function sendToClient(
	msg: string | Uint8Array,
	offset: number,
	length: number,
	port?: number,
	address?: string,
	callback?: (error: Error | null, bytes: number) => void,
	stateForRetry?: string
): void {
	let retried = 0;

	function sendResponse() {
		console.log(`sending response... (try: ${retried})`);
		server.send(msg, offset, length, port, address, (error: Error | null, bytes: number) => {
			// all good

			if (callback) callback(error, bytes);
		});

		if (stateForRetry && retried < 3) {
			// timeout[stateForRetry] = setTimeout(sendResponse, 600 * (retried+1));
		}
		retried++;
	}

	sendResponse();
}

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

		sendToClient(response, 0, response.length, rinfo.port, rinfo.address, function(err, _bytes) {
			if (err) {
				console.log('Error sending response to ', rinfo);
			}
		});
	}

	if (packet.attributes['EAP-Message']) {
		const state = (packet.attributes.State && packet.attributes.State.toString()) || makeid(16);

		if (timeout[state]) {
			clearTimeout(timeout[state]);
		}

		const handlers = {
			response: (EAPMessage: Buffer) => {
				const attributes: any = [['State', Buffer.from(state)]];
				let sentDataSize = 0;
				do {
					if (EAPMessage.length > 0) {
						attributes.push([
							'EAP-Message',
							EAPMessage.slice(sentDataSize, sentDataSize + MAX_RADIUS_ATTRIBUTE_SIZE)
						]);
						sentDataSize += MAX_RADIUS_ATTRIBUTE_SIZE;
					}
				} while (sentDataSize < EAPMessage.length);

				const response = radius.encode_response({
					packet,
					code: 'Access-Challenge',
					secret: argv.secret,
					attributes
				});

				waitForNextMsg[state] = newDeferredPromise();

				sendToClient(
					response,
					0,
					response.length,
					rinfo.port,
					rinfo.address,
					function(err, _bytes) {
						if (err) {
							console.log('Error sending response to ', rinfo);
						}
					},
					state
				);

				return waitForNextMsg[state].promise;
			},
			checkAuth
		};

		if (waitForNextMsg[state]) {
			const identifier = packet.attributes['EAP-Message'].slice(1, 2).readUInt8(0); // .toString('hex');
			waitForNextMsg[state].resolve({ response: handlers.response, identifier });
		}

		// EAP MESSAGE
		eapHandler.handleEAPMessage(packet.attributes['EAP-Message'], state, handlers);
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
