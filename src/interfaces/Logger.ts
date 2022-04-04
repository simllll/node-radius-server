export interface ILogger {
	log(message: any, ...optionalParams: any[]): void;
	error(message: any, ...optionalParams: any[]): void;
	warn(message: any, ...optionalParams: any[]): void;
	debug(message: any, ...optionalParams: any[]): void;
	verbose?(message: any, ...optionalParams: any[]): void;
}
