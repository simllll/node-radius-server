import { UDPServer } from './server/UDPServer';
import { RadiusService } from './radius/RadiusService';

import * as config from '../config';
import { Authentication } from './auth';
import { IAuthentication } from './types/Authentication';
import { startTLSServer } from './tls/crypt';

/* test node version */
const testSocket = startTLSServer();
if (typeof (testSocket.tls as any).exportKeyingMaterial !== 'function') {
	console.error('UNSUPPORTED NODE VERSION FOUND!!')
	console.log('run "sudo npx n nightly" to get nightly build of node js.');
	process.exit(-1);
}

console.log(`Listener Port: ${config.port || 1812}`);
console.log(`RADIUS Secret: ${config.secret}`);
console.log(`Auth Mode: ${config.authentication}`);

(async () => {
	/* configure auth mechansim */
	let auth: IAuthentication;
	try {
		const AuthMechanismus = (await import(`./auth/${config.authentication}`))[
			config.authentication
		];
		auth = new AuthMechanismus(config.authenticationOptions);
	} catch (err) {
		console.error('cannot load auth mechanismus', config.authentication);
		throw err;
	}
	// start radius server
	const authentication = new Authentication(auth);

	const server = new UDPServer(config.port);
	const radiusService = new RadiusService(config.secret, authentication);

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
