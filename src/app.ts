import yargs from 'yargs';

// eslint-disable-next-line import/extensions
import config from '../config.js';
import { Authentication } from './auth.js';
import { IAuthentication } from './interfaces/Authentication.js';
import { RadiusServer } from './radius/RadiusServer.js';
import { ConsoleLogger, LogLevel } from './logger/ConsoleLogger.js';


(async () => {
	// kinda ugly workaround for yargs
	const myYargs = await yargs() as unknown as typeof yargs;

	const logger = new ConsoleLogger(
		process.env.NODE_ENV === 'development' ? LogLevel.debug : LogLevel.log
	);

	const { argv } = myYargs
		.usage('NODE RADIUS Server\nUsage: radius-server')
		.example('radius-server --port 1812 -s radiussecret', 'start on port 1812 with a secret')
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
		.string(['secret', 'authentication']) as {
		argv: { port?: number; secret?: string; authentication?: string; authenticationOptions?: any };
	};

	logger.log(`Listener Port: ${argv.port || 1812}`);
	logger.log(`RADIUS Secret: ${argv.secret}`);
	logger.log(`Auth ${argv.authentication}`);
	logger.debug(`Auth Config: ${JSON.stringify(argv.authenticationOptions, undefined, 3)}`);

	// configure auth mechanism
	let auth: IAuthentication;
	try {
		const AuthMechanism = (await import(`./auth/${config.authentication}.js`))[config.authentication];
		auth = new AuthMechanism(config.authenticationOptions, logger);
	} catch (err) {
		logger.error('cannot load auth mechanisms', config.authentication);
		throw err;
	}
	// start radius server
	const authentication = new Authentication(auth, logger);

	const server = new RadiusServer({
		secret: config.secret,
		port: config.port,
		address: '0.0.0.0',
		tlsOptions: config.certificate,
		authentication,
		logger,
	});

	// start server
	await server.start();
})();
