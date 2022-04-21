import { ILogger } from '../interfaces/Logger.js';

export enum LogLevel {
	Verbose = 'verbose',
	Debug = 'debug',
	Log = 'log',
	Warn = 'warn',
	Error = 'error',
}

export class ConsoleLogger implements ILogger {
	constructor(private readonly logLevel: LogLevel) {
		this.debug('ConsoleLogger', `initialized with LogLevel: ${logLevel}`);
	}

	public error(context: string, message: string, ...optionalParams: unknown[]): void {
		switch (this.logLevel) {
			case LogLevel.Verbose:
			case LogLevel.Debug:
			case LogLevel.Log:
			case LogLevel.Warn:
			case LogLevel.Error:
				// eslint-disable-next-line no-console
				console.error(`[${context ?? '?'}]`, message, ...optionalParams);
				break;
			default:
		}
	}

	public warn(context: string, message: string, ...optionalParams: unknown[]): void {
		switch (this.logLevel) {
			case LogLevel.Verbose:
			case LogLevel.Debug:
			case LogLevel.Log:
			case LogLevel.Warn:
				// eslint-disable-next-line no-console
				console.warn(`[${context ?? '?'}]`, message, ...optionalParams);
				break;
			default:
		}
	}

	public log(context: string, message: string, ...optionalParams: unknown[]): void {
		switch (this.logLevel) {
			case LogLevel.Verbose:
			case LogLevel.Debug:
			case LogLevel.Log:
				// eslint-disable-next-line no-console
				console.log(`[${context ?? '?'}]`, message, ...optionalParams);
				break;
			default:
		}
	}

	public debug(context: string, message: string, ...optionalParams: unknown[]): void {
		switch (this.logLevel) {
			case LogLevel.Verbose:
			case LogLevel.Debug:
				// eslint-disable-next-line no-console
				console.debug(`[${context ?? '?'}]`, message, ...optionalParams);
				break;
			default:
		}
	}

	public verbose(context: string, message: string, ...optionalParams: unknown[]): void {
		switch (this.logLevel) {
			case LogLevel.Verbose:
				// eslint-disable-next-line no-console
				console.debug(`[${context ?? '?'}]`, message, ...optionalParams);
				break;
			default:
		}
	}
}
