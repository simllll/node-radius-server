import { SecureContextOptions } from 'tls';
import { IAuthentication } from './Authentication';
import { ILogger } from './Logger';

export interface IRadiusServerOptions {
	logger: ILogger;
	secret: string;
	port: number;
	address: string;
	tlsOptions: SecureContextOptions;
	authentication: IAuthentication;
}
