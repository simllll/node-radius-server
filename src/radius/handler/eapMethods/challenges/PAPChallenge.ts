import debug from 'debug';
import { IEAPChallenge } from '../../../../types/EAPChallenge';

const log = debug('radius:eap:papchallenge');

export class PAPChallenge implements IEAPChallenge {
	// i couldn't find any documentation about it, therefore best guess how this is processed...
	// http://www.networksorcery.com/enp/rfc/rfc1334.txt ?

	decode(data: Buffer) {
		const usrNameLength = data.slice(7, 8).readUInt8(0);
		const user = data.slice(8, usrNameLength);
		log('user', user, user.toString().trim());

		let pwdStart = usrNameLength; // data.slice(usrNameLength);
		const passwordDelimeter = Buffer.from([0x02, 0x40, 0x00, 0x00]);
		let found = false;

		let pwd: Buffer;

		do {
			const possibleDelimieter = data.slice(pwdStart, pwdStart + passwordDelimeter.length);
			if (possibleDelimieter.equals(passwordDelimeter)) {
				found = true;
			}
			if (!found) {
				pwdStart++;
			}
		} while (!found && pwdStart < data.length);
		if (!found) {
			throw new Error("couldn't extract password");
		}
		// log('pwdStart+passwordDelimeter.length', pwdStart+passwordDelimeter.length);
		// log('length', pwdStart + data.readUInt8(pwdStart+passwordDelimeter.length));
		// first byte is a length property.. we ignore for now
		pwd = data.slice(pwdStart + passwordDelimeter.length + 1); // , pwdStart+ data.readUInt8(pwdStart+passwordDelimeter.length));
		// trim pwd
		pwd = pwd.slice(0, pwd.indexOf(0x00));

		log('pwd', pwd, pwd.toString().trim().length, pwd.toString());

		return {
			username: user.toString(),
			password: pwd.toString()
		};
	}
}
