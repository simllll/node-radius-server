import { ILogger } from '../interfaces/Logger';

export enum LogLevel {
	verbose,
	debug,
	log,
	warn,
	error,
}

export class ConsoleLogger implements ILogger {
	constructor(private readonly logLevel: LogLevel) {}

	error(message: unknown, ...optionalParams: unknown[]): void {
		if (this.logLevel >= LogLevel.error) {
			console.error(message, ...optionalParams);
		}
	}

	warn(message: unknown, ...optionalParams: unknown[]): void {
		if (this.logLevel >= LogLevel.warn) {
			console.warn(message, ...optionalParams);
		}
	}

	log(message: unknown, ...optionalParams: unknown[]): void {
		if (this.logLevel >= LogLevel.log) {
			console.log(message, ...optionalParams);
		}
	}

	debug(message: unknown, ...optionalParams: unknown[]): void {
		if (this.logLevel >= LogLevel.debug) {
			console.debug(message, ...optionalParams);
		}
	}

	verbose(message: unknown, ...optionalParams: unknown[]): void {
		if (this.logLevel >= LogLevel.verbose) {
			console.debug(message, ...optionalParams);
		}
	}
}
