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
		if (this.logLevel >= LogLevel.Error) {
			console.error(message, ...optionalParams);
		}
	}

	warn(message: unknown, ...optionalParams: unknown[]): void {
		if (this.logLevel >= LogLevel.Warn) {
			console.warn(message, ...optionalParams);
		}
	}

	log(message: unknown, ...optionalParams: unknown[]): void {
		if (this.logLevel >= LogLevel.Log) {
			console.log(message, ...optionalParams);
		}
	}

	debug(message: unknown, ...optionalParams: unknown[]): void {
		if (this.logLevel >= LogLevel.Debug) {
			console.debug(message, ...optionalParams);
		}
	}

	verbose(message: unknown, ...optionalParams: unknown[]): void {
		if (this.logLevel >= LogLevel.Verbose) {
			console.debug(message, ...optionalParams);
		}
	}
}
