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

	error(context: string, message: unknown, ...optionalParams: unknown[]): void {
		switch (this.logLevel) {
			case LogLevel.Verbose:
			case LogLevel.Debug:
			case LogLevel.Log:
			case LogLevel.Warn:
			case LogLevel.Error:
				console.error(`[${context}]`, message, ...optionalParams);
				break;
			default:
		}
	}

	warn(context: string, message: unknown, ...optionalParams: unknown[]): void {
		switch (this.logLevel) {
			case LogLevel.Verbose:
			case LogLevel.Debug:
			case LogLevel.Log:
			case LogLevel.Warn:
				console.warn(`[${context}]`, message, ...optionalParams);
				break;
			default:
		}
	}

	log(context: string, message: unknown, ...optionalParams: unknown[]): void {
		switch (this.logLevel) {
			case LogLevel.Verbose:
			case LogLevel.Debug:
			case LogLevel.Log:
				console.log(`[${context}]`, message, ...optionalParams);
				break;
			default:
		}
	}

	debug(context: string, message: unknown, ...optionalParams: unknown[]): void {
		switch (this.logLevel) {
			case LogLevel.Verbose:
			case LogLevel.Debug:
				console.debug(`[${context}]`, message, ...optionalParams);
				break;
			default:
		}
	}

	verbose(context: string, message: unknown, ...optionalParams: unknown[]): void {
		switch (this.logLevel) {
			case LogLevel.Verbose:
				console.debug(`[${context}]`, message, ...optionalParams);
				break;
			default:
		}
	}

	context(context: string) {
		return {
			context: this.context.bind(this),
			error: (message: unknown, ...args) => this.error(context, message, ...args),
			warn: (message: unknown, ...args) => this.warn(context, message, ...args),
			log: (message: unknown, ...args) => this.log(context, message, ...args),
			debug: (message: unknown, ...args) => this.debug(context, message, ...args),
			verbose: (message: unknown, ...args) => this.verbose(context, message, ...args),
		};
	}
}
