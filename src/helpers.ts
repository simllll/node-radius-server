export function makeid(length) {
	let result = '';
	const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	const charactersLength = characters.length;
	for (let i = 0; i < length; i++) {
		result += characters.charAt(Math.floor(Math.random() * charactersLength));
	}
	return result;
}

// by RFC Radius attributes have a max length
// https://tools.ietf.org/html/rfc6929#section-1.2
export const MAX_RADIUS_ATTRIBUTE_SIZE = 253;

export interface IDeferredPromise {
	promise: Promise<any>;
	resolve: (value?: unknown) => Promise<void>;
	reject: (reason?: any) => Promise<void>;
}

export const newDeferredPromise = (): IDeferredPromise => {
	if (Promise && !('deferred' in Promise)) {
		let fResolve;
		let fReject;

		const P = new Promise((resolve, reject) => {
			fResolve = resolve;
			fReject = reject;
		});
		return {
			promise: P,
			resolve: fResolve,
			reject: fReject,
		};
	}

	return (Promise as any).deferred;
};

export const delay = (timeout: number) =>
	new Promise((resolve) => setTimeout(() => resolve(), timeout));
