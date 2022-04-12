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
		console.log(`ConsoleLogger initialized with LogLevel: ${logLevel}`);
	}

	error(message: unknown, ...optionalParams: unknown[]): void {
		switch (this.logLevel) {
			case LogLevel.Error:
				console.error(message, ...optionalParams);
				break;
			default:
		}
	}

	warn(message: unknown, ...optionalParams: unknown[]): void {
		switch (this.logLevel) {
			case LogLevel.Warn:
			case LogLevel.Error:
				console.warn(message, ...optionalParams);
				break;
			default:
		}
	}

	log(message: unknown, ...optionalParams: unknown[]): void {
		switch (this.logLevel) {
			case LogLevel.Log:
			case LogLevel.Warn:
			case LogLevel.Error:
				console.log(message, ...optionalParams);
				break;
			default:
		}
	}

	debug(message: unknown, ...optionalParams: unknown[]): void {
		switch (this.logLevel) {
			case LogLevel.Debug:
			case LogLevel.Log:
			case LogLevel.Warn:
			case LogLevel.Error:
				console.debug(message, ...optionalParams);
				break;
			default:
		}
	}

	verbose(message: unknown, ...optionalParams: unknown[]): void {
		// output all
		console.debug(message, ...optionalParams);
	}
}
