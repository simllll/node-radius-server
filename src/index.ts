import { IAuthentication } from './interfaces/Authentication.js';
import { IRadiusServerOptions } from './interfaces/RadiusServerOptions.js';
import { RadiusServer } from './radius/RadiusServer.js';
import { ILogger } from './interfaces/Logger.js';

export {
	IAuthentication as RadiusAuthentication,
	IRadiusServerOptions as RadiusServerOptions,
	RadiusServer,
	ILogger as RadiusLogger,
};

/*
	Export RadiusServer and relevant interfaces, so it can be used in other projects (e.g. a NestJS backend)
	const radiusServer = new RadiusServer({
			logger: this.logger,
			secret: this.secret,
			port: this.port,
			address: this.hostname,
			tlsOptions: this.tlsOptions,
			authentication: this
	});
	await radiusServer.start();
 */
