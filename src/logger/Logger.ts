import { ILogger } from '../interfaces/Logger.js';

export class Logger implements ILogger {
	private static instanceLogger?: ILogger;

	public constructor(public readonly context?: string) {}

	public static registerLogger(logger: ILogger): void {
		this.instanceLogger = logger;
	}

	public log(message: string, ...optionalParams: unknown[]): void {
		Logger.instanceLogger?.log(this.context ?? '?', message, ...optionalParams);
	}

	public error(message: string, ...optionalParams: unknown[]): void {
		Logger.instanceLogger?.error(this.context ?? '?', message, ...optionalParams);
	}

	public warn(message: string, ...optionalParams: unknown[]): void {
		Logger.instanceLogger?.warn(this.context ?? '?', message, ...optionalParams);
	}

	public debug(message: string, ...optionalParams: unknown[]): void {
		Logger.instanceLogger?.debug(this.context ?? '?', message, ...optionalParams);
	}

	public verbose(message: string, ...optionalParams: unknown[]): void {
		Logger.instanceLogger?.verbose(this.context ?? '?', message, ...optionalParams);
	}
}
