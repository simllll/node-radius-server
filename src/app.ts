import * as yargs from 'yargs';
import { UDPServer } from './server/UDPServer';
import { RadiusService } from './radius/RadiusService';

import * as config from '../config';
import { Authentication } from './auth';
import { IAuthentication } from './types/Authentication';
import { startTLSServer } from './tls/crypt';

/* test node version */
const testSocket = startTLSServer();
if (typeof (testSocket.tls as any).exportKeyingMaterial !== 'function') {
	console.error(`UNSUPPORTED NODE VERSION (${process.version}) FOUND!!`);

	console.log('min version supported is node js 14. run "sudo npx n 14"');
	process.exit(-1);
}

const { argv } = yargs
	.usage('NODE RADIUS Server\nUsage: radius-server')
	.example('radius-server --port 1812 -s radiussecret')
	.default({
		port: config.port || 1812,
		s: config.secret || 'testing123',
		authentication: config.authentication,
		authenticationOptions: config.authenticationOptions,
	})
	.describe('port', 'RADIUS server listener port')
	.alias('s', 'secret')
	.describe('secret', 'RADIUS secret')
	.number('port')
	.string(['secret', 'authentication']);

console.log(`Listener Port: ${argv.port || 1812}`);
console.log(`RADIUS Secret: ${argv.secret}`);
console.log(`Auth ${argv.authentication}`);
console.log(`Auth Config: ${JSON.stringify(argv.authenticationOptions, undefined, 3)}`);

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
