import { SecureContextOptions } from 'tls';
import { IAuthentication } from './Authentication';
import { ILogger } from './Logger';

export interface IRadiusServerOptions {
	secret: string;
	tlsOptions: SecureContextOptions;
	authentication: IAuthentication;
	vlan?: number;
	logger?: ILogger;
	port?: number;
	address?: string;
}
