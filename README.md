Basic RADIUS Server for node.js for Google LDAP Service and WPA2 Enteprise WLAN Authentification.

- supports LDAP Authentification Backend
- supports WPA2 Entprise (TTLS over PAP)

Protect your WIFI access with a username and password by a credential provider you already use!

## Known Issues / Disclaimer

This is a first implementation draft, which is currently only working with a nodejs fork (see https://github.com/nodejs/node/pull/31814).

- PAP / CHAP RFC not found to implement this correctly
- a lot of bugs

CONTRIBUTIONS WELCOME! If you are willing to help, just open a PR or contact me via bug system or simon.tretter@hokify.com.

## Motivation

### Why not Freeradius?

There are several reasons why I started implementing this radius server in node js. We are using
freeradius right now, but have several issues which are hard to tackle due to the reason that freeradius
is a complex software and supports many uses cases. It is also written in C++ and uses threads behind the scene.
Therefore it's not easy to extend or modify it, or even bring new feature in.
The idea of this project is to make a super simple node radius server, which is async by default. No complex
thread handling, no other fancy thing. The basic goal is to make WPA2 authenticiation easy again.

### 802.11x protocol in node

Another motivation is that it is very exciting to see how wireless protocols have evolved, and see
how a implementation like TTLS works.

### Few alternatives (only non-free ones like Jumpcloud...)

Furthermore there are few alternatives out there, e.g. jumpcloud is non-free and I couldn't find many others.

### Vision

As soon as I understood the TTLS PAP Tunnel approach, I had this vision of making Wlan Authentification easy
for everyone. Why limit it to something "complex" like LDAP and co. This library aims to make it easy for everyone
to implement either their own authentication mechanismus (e.g. against a database), or provides some mechansimns
out of the box (e.g. imap, static, ldap,..).

## Installation

    npm install
    npm run build

## Introduction

This app provides a radius server to authenticate against google's SLDAP service. To get this running
you need:

1.  Running LDAP Service (E.g. Google Suite Enterprise or Gloud Identity Premium)
2.  Optional: Create your own SSL certificate (e.g. self signed via npm run create-certificate)
3.  Check config.js and adapt to your needs

- configure authentication:
set authenticaiton to one of the provided authenticators.

```js
var config = {
	// ....
	authentication: 'GoogleLDAPAuth',
	authenticationOptions: {
		base: 'dc=hokify,dc=com'
	}
};
```

- set radius secret

4.  Install und build server: npm install && npm run build
5.  Start server "npm run start"

## Configuration

see config.js in root



### Authentications

#### Google LDAP

google ldap optimized authenticiation implementaiton

```typescript
interface IGoogleLDAPAuthOptions {
	/** base DN
	 *  e.g. 'dc=hokify,dc=com', */
	base: string;
	/** tls options
	 * e.g. {
			key: fs.readFileSync('ldap.gsuite.hokify.com.40567.key'),
			cert: fs.readFileSync('ldap.gsuite.hokify.com.40567.crt')
		} */
	tlsOptions: tls.TlsOptions;
}
```

Example
```js
c = {
	// GoogleLDAPAuth (optimized for google auth)
	authentication: 'GoogleLDAPAuth',
	authenticationOptions: {
		base: 'dc=hokify,dc=com',
		tlsOptions: {
			key: fs.readFileSync('ldap.gsuite.hokify.com.40567.key'),
			cert: fs.readFileSync('ldap.gsuite.hokify.com.40567.crt')
		}
	}
}
```

#### LDAP

ldap authentication

```typescript
interface ILDAPAuthOptions {
	/** ldap url
	 * e.g. ldaps://ldap.google.com
	 */
	url: string;
	/** base DN
	 *  e.g. 'dc=hokify,dc=com', */
	base: string;
	/** tls options
	 * e.g. {
			key: fs.readFileSync('ldap.gsuite.hokify.com.40567.key'),
			cert: fs.readFileSync('ldap.gsuite.hokify.com.40567.crt'),
			servername: 'ldap.google.com'
		} */
	tlsOptions?: any;
	/**
	 * searchFilter
	 */
	searchFilter?: string;
}
```

Example
```js
c = {
	authentication: 'LDAPAuth',
	authenticationOptions: {
		url: 'ldaps://ldap.google.com',
		base: 'dc=hokify,dc=com',
		tlsOptions: {
			key: fs.readFileSync('ldap.gsuite.hokify.com.40567.key'),
			cert: fs.readFileSync('ldap.gsuite.hokify.com.40567.crt'),
			servername: 'ldap.google.com'
		}
	}
}
```

#### IMAP

imap authenticiation

```typescript
interface IIMAPAuthOptions {
	host: string;
	port?: number;
	useSecureTransport?: boolean;
	validHosts?: string[];
}
```

Example
```js
c = {
	authentication: 'IMAPAuth',
	authenticationOptions: {
		host: 'imap.gmail.com',
		port: 993,
		useSecureTransport: true,
		validHosts: ['hokify.com']
	}
	}
```

#### SMTP

smtp authenticiation

```typescript
interface ISMTPAuthOptions {
	host: string;
	port?: number;
	useSecureTransport?: boolean;
	validHosts?: string[];
}
```

Example
```js
c = {
	authentication: 'IMAPAuth',
	authenticationOptions: {
		host: 'smtp.gmail.com',
		port: 465,
		useSecureTransport: true,
		validHosts: ['gmail.com']
	}
}
```

#### Static Auth

static authenticiation

```typescript
interface IStaticAuthOtions {
	validCrentials: {
		username: string;
		password: string;
	}[];
}
```

Example
```js
c = {
	authentication: 'StaticAuth',
	authenticationOptions: {
		validCredentials: [
            { username: 'test', password: 'pwd' },
            { username: 'user1', password: 'password' },
            { username: 'admin', password: 'cool' }
      ]
	}
}
```

## Usage

Ensure you have installed latest nightly node version and run:

    npm run start
