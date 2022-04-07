import { SecureContextOptions } from 'tls';
import { IAuthentication } from './Authentication';
import { ILogger } from './Logger';
import { LogLevel } from '../logger/ConsoleLogger';

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
