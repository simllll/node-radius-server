import { SecureContextOptions } from 'tls';
import { IAuthentication } from './Authentication.js';
import { ILogger } from './Logger.js';
import { LogLevel } from '../logger/ConsoleLogger.js';

export type RadiusServerOptions = IRadiusServerOptions &
	(
		| {
				logger?: ILogger;
		  }
		| {
				logLevel: LogLevel;
		  }
	);

interface IRadiusServerOptions {
	secret: string;
	tlsOptions: SecureContextOptions;
	authentication: IAuthentication;
	vlan?: number;
	port?: number;
	address?: string;
}
