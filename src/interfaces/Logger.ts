export interface ILogger {
	log(context: string, message: unknown, ...optionalParams: any[]): void;
	error(context: string, message: unknown, ...optionalParams: any[]): void;
	warn(context: string, message: unknown, ...optionalParams: any[]): void;
	debug(context: string, message: unknown, ...optionalParams: any[]): void;
	verbose?(context: string, message: unknown, ...optionalParams: any[]): void;
	context(context: string): IContextLogger;
}

export interface IContextLogger extends ILogger {
	log(message: unknown, ...optionalParams: any[]): void;
	error(message: unknown, ...optionalParams: any[]): void;
	warn(message: unknown, ...optionalParams: any[]): void;
	debug(message: unknown, ...optionalParams: any[]): void;
	verbose?(message: unknown, ...optionalParams: any[]): void;
}
