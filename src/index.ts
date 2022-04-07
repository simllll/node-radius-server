import { IAuthentication } from './interfaces/Authentication';
import { RadiusServerOptions } from './interfaces/RadiusServerOptions';
import { RadiusServer } from './radius/RadiusServer';

export { IAuthentication as RadiusAuthentication, RadiusServerOptions, RadiusServer };

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
