import * as NodeCache from 'node-cache';
import * as events from 'events';
import * as tls from 'tls';
import { createSecureContext } from 'tls';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as DuplexPair from 'native-duplexpair';
import { makeid } from '../helpers';

// https://nodejs.org/api/tls.html
const tlsOptions = {
	cert: fs.readFileSync('./ssl/public-cert.pem'),
	key: fs.readFileSync('./ssl/private-key.pem'),
	ecdhCurve: 'auto'
};
const secureContext = createSecureContext(tlsOptions);
export const openTLSSockets = new NodeCache({ useClones: false, stdTTL: 3600 }); // keep sockets for about one hour

export function startTLSServer(): events.EventEmitter {
	const duplexpair = new DuplexPair();
	const emitter = new events.EventEmitter();

	const cleartext = new tls.TLSSocket(duplexpair.socket1, {
		secureContext,
		isServer: true
	});
	const encrypted = duplexpair.socket2;

	emitter.on('send', (data: Buffer) => {
		encrypted.write(data);
		// encrypted.sync();
	});

	encrypted.on('data', (data: Buffer) => {
		// console.log('encrypted data', data, data.toString());
		emitter.emit('response', data);
	});

	cleartext.on('secure', () => {
		const cipher = cleartext.getCipher();

		/*
        console.log('Authorized', cleartext.authorized);
        console.log('getTLSTicket', cleartext.getTLSTicket());
        console.log('getEphemeralKeyInfo', cleartext.getEphemeralKeyInfo());
        console.log('getPeerCertificate', cleartext.getPeerCertificate());
        console.log('getSharedSigalgs', cleartext.getSharedSigalgs());
        console.log('getCertificate', cleartext.getCertificate());
        console.log('getSession', cleartext.getSession());
        */

		if (cipher) {
			console.log(`TLS negotiated (${cipher.name}, ${cipher.version})`);
		}

		cleartext.on('data', (data: Buffer) => {
			// console.log('cleartext data', data, data.toString());
			emitter.emit('incoming', data);
		});

		cleartext.once('close', (data: Buffer) => {
			console.log('cleartext close');
			emitter.emit('end');
		});

		cleartext.on('keylog', line => {
			console.log('############ KEYLOG #############', line);
			// cleartext.getTicketKeys()
		});

		console.log('*********** new client connection established / secured ********');
		//        this.emit('secure', securePair.cleartext);
		//        this.encryptAllFutureTraffic();
	});

	cleartext.on('error', (err?: Error) => {
		console.log('cleartext error', err);

		encrypted.destroy();
		cleartext.destroy(err);

		emitter.emit('end');
	});

	return emitter;
}

function md5Hex(buffer: Buffer): Buffer {
	const hasher = crypto.createHash('md5');
	hasher.update(buffer);
	return hasher.digest(); // new Buffer(hasher.digest("binary"), "binary");
}

export function encodeTunnelPW(key: Buffer, authenticator: Buffer, secret: string): Buffer {
	// see freeradius TTLS implementation how to obtain "key"......

	// key should be:
	// https://www.openssl.org/docs/man1.0.2/man3/SSL_export_keying_material.html
	// https://github.com/nodejs/ffi/blob/master/deps/openssl/openssl/doc/man3/SSL_export_keying_material.pod

	// but not available in NODE JS

	console.log('KEY', key);
	console.log('authenticator', authenticator);
	console.log('secret', secret);
	// https://tools.ietf.org/html/rfc2548

	/**
     * Salt
     The Salt field is two octets in length and is used to ensure the
     uniqueness of the keys used to encrypt each of the encrypted
     attributes occurring in a given Access-Accept packet.  The most
     significant bit (leftmost) of the Salt field MUST be set (1).  The
     contents of each Salt field in a given Access-Accept packet MUST
     be unique.
     */
	const salt = Buffer.concat([
		// eslint-disable-next-line no-bitwise
		Buffer.from((Number(makeid(1)) & 0b10000000).toString()), // ensure left most bit is set (1)
		Buffer.from(makeid(1))
	]);

	console.log('salt', salt);
	// ensure left most bit is set to 1

	/*
   String
   The plaintext String field consists of three logical sub-fields:
   the Key-Length and Key sub-fields (both of which are required),
   and the optional Padding sub-field.  The Key-Length sub-field is
   one octet in length and contains the length of the unencrypted Key
   sub-field.  The Key sub-field contains the actual encryption key.
   If the combined length (in octets) of the unencrypted Key-Length
   and Key sub-fields is not an even multiple of 16, then the Padding
   sub-field MUST be present.  If it is present, the length of the
   Padding sub-field is variable, between 1 and 15 octets.  The
   String field MUST be encrypted as follows, prior to transmission:

   Construct a plaintext version of the String field by concate-
   nating the Key-Length and Key sub-fields.  If necessary, pad
   the resulting string until its length (in octets) is an even
   multiple of 16.  It is recommended that zero octets (0x00) be
   used for padding.  Call this plaintext P.
   */

	console.log('key', key.length, key);
	let P = Buffer.concat([new Uint8Array([key.length]), key]); // + key + padding;

	// fill up with 0x00 till we have % 16
	while (P.length % 16 !== 0) {
		P = Buffer.concat([P, Buffer.from([0x00])]);
	}
	// console.log('PLAINTEXT', P.length, P);
	/*
   Call the shared secret S, the pseudo-random 128-bit Request
   Authenticator (from the corresponding Access-Request packet) R,
   and the contents of the Salt field A.  Break P into 16 octet
   chunks p(1), p(2)...p(i), where i = len(P)/16.  Call the
   ciphertext blocks c(1), c(2)...c(i) and the final ciphertext C.
   Intermediate values b(1), b(2)...c(i) are required.  Encryption
   is performed in the following manner ('+' indicates
   concatenation):
   */

	const p: Buffer[] = [];
	for (let i = 0; i < P.length; i += 16) {
		p.push(P.slice(i, i + 16));
	}

	const S = secret;
	const R = authenticator;
	const A = salt;

	// console.log('S', S);
	// console.log('R', R);
	// console.log('A', A);

	// const P = Buffer.alloc(16);

	let C;
	const c: { [key: number]: Buffer } = {};
	const b: { [key: number]: Buffer } = {};

	// console.log('S + R + A', S + R + A);

	for (let i = 0; i < p.length; i++) {
		// one octet is 8.. therefore +=2 means next 16
		if (!i) {
			b[i] = md5Hex(Buffer.concat([Buffer.from(S), R, A]));
		} else {
			b[i] = md5Hex(Buffer.concat([Buffer.from(S), c[i - 1]]));
		}

		c[i] = Buffer.alloc(16); // ''; //p[i];
		for (let n = 0; n < p[i].length; n++) {
			// eslint-disable-next-line no-bitwise
			c[i][n] = p[i][n] ^ b[i][n];
		}

		// console.log('c['+i+']', c[i]);
		// console.log('b['+i+']', b[i]);

		C = C ? Buffer.concat([C, c[i]]) : c[i];
	}

	const bufferC = Buffer.from(C);
	console.log('BUFFER C', bufferC.length, bufferC);
	return Buffer.concat([salt, bufferC]);
	/*
   Zorn                         Informational                     [Page 21]

   RFC 2548      Microsoft Vendor-specific RADIUS Attributes     March 1999


   b(1) = MD5(S + R + A)    c(1) = p(1) xor b(1)   C = c(1)
   b(2) = MD5(S + c(1))     c(2) = p(2) xor b(2)   C = C + c(2)
   .                      .
   .                      .
   .                      .
   b(i) = MD5(S + c(i-1))   c(i) = p(i) xor b(i)   C = C + c(i)

   The   resulting   encrypted   String   field    will    contain
   c(1)+c(2)+...+c(i).
   */
}
