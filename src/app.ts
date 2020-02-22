import { GoogleLDAPAuth } from './auth/google-ldap';
import { UDPServer } from './server/UDPServer';
import { RadiusService } from './radius/RadiusService';

import * as config from '../config';

console.log(`Listener Port: ${config.port || 1812}`);
console.log(`RADIUS Secret: ${config.secret}`);
console.log(`Auth Mode: ${config.authentication}`);

// const ldap = new LDAPAuth({url: 'ldap://ldap.google.com', base: 'dc=hokify,dc=com', uid: 'uid', tlsOptions});

const ldap = new GoogleLDAPAuth(
	config.authenticationOptions.url,
	config.authenticationOptions.base
);

const server = new UDPServer(config.port);
const radiusService = new RadiusService(config.secret, ldap);

(async () => {
	server.on('message', async (msg, rinfo) => {
		const response = await radiusService.handleMessage(msg);

		if (response) {
			server.sendToClient(
				response.data,
				rinfo.port,
				rinfo.address,
				(err, _bytes) => {
					if (err) {
						console.log('Error sending response to ', rinfo);
					}
				},
				response.expectAcknowledgment
			);
		}
	});

	// start server
	await server.start();
})();
