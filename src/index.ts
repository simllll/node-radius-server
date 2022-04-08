export { IAuthentication as RadiusAuthentication } from './interfaces/Authentication.js';
export { RadiusServerOptions } from './interfaces/RadiusServerOptions.js';
export { RadiusServer } from './radius/RadiusServer.js';

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
