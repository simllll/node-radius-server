export interface ILogger {
	log(context: string, message: string, ...optionalParams: unknown[]): void;
	error(context: string, message: string, ...optionalParams: unknown[]): void;
	warn(context: string, message: string, ...optionalParams: unknown[]): void;
	debug(context: string, message: string, ...optionalParams: unknown[]): void;
	verbose(context: string, message: string, ...optionalParams: unknown[]): void;
}
