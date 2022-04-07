# easy extensible NodeJS RADIUS Server

- supports different authentification backends
    - LDAP (e.g. for Google LDAP Service, but also any other LDAP service)
    - HTTP
    - IMAP
    - SMTP
    - Predefined / Static username and password
- supports WPA2 Enterprise
    - TTLS
    - PAP / GTC

Protect your WIFI access with a username and password by a credential provider you already use!

Authentication tested with Windows, Linux, Android and Apple devices.

## Introduction

This app provides a radius server to authenticate against an authentication service. To get this running
you need:

1.  An running Auth Service (e.g. LDAP Service / Google Suite Enterprise / Gloud Identity Premium)
2.  Optional: Create your own SSL certificate (e.g. self signed via npm run create-certificate)
3.  Check config.js and adapt to your needs

- configure authentication:
  set authenticaiton to one of the [provided authenticators](src/auth/README.md), e.g.:

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

## Quick start for using it with Google LDAP

1. Install node js => 13.10.1
    - easiest way is to install a node js version from nodejs.org or run "npx n latest" to install latest version.
2. Check out the config options, e.g. for google ldap, download your certificates from http://admin.google.com/ -> Apps -> LDAP -> Client
download the files and name them "ldap.gsuite.key" and "ldap.gsuite.crt" accordingly (Ensure you have activated your newly created LDAP Client in Google Admin).
3. Switch to this directory and run "npx radius-server -s YourRadiusSecret"
4. Log into your WLAN Controller and configure the radius server to your newly running radius
5. On your clients, just connect to the WLAN, the clients should figure out the correct method by their own,
if they don't use: WPA2-Enterprise -> EAP-TTLS -> PAP / CHAP
6. Log in with your google credentials (email + password, ... e.g. youremail@yourcompany.com)

## Configuration

For authentication see [Authentication Details](src/auth/README.md).
For general config options run with --help or see see [config.js](config.js) in root.

## Installation

    npm install
    npm run build

## Usage

Ensure you have installed latest node version (>= 13.10.1) and run:

    npm run start

# Use as module

```
npm install radius-server
```

This allows this module to be used in other node projects:
```ts
  import { RadiusServer } from 'radius-server';

  const radiusServer = new RadiusServer({
      logger: this.logger,
      secret: this.secret,
      port: this.port,
      address: this.hostname,
      tlsOptions: this.tlsOptions,
      authentication: this
  });
  await radiusServer.start();
 ```

## Known Issues / Disclaimer

Support for this has landed in node 13.10.1, therefore ensure you have installed at least this node version.

- MD5 Challenge not implemented, but RFC says this is mandatory ;-) (no worries, it isn't)
- Inner Tunnel does not act differently, even though spec says that EAP-message are not allowed to get fragmented,
this is not a problem right now, as the messages of the inner tunnel are small enough, but it could be a bug in the future.
ways to approach this: refactor that the inner tunnel can set max fragment size, or rebuild eap fragments in ttls after inner tunnel response
- minor security issues regarding session resumption. It could theoretically be possible to hijack when the auth is actually rejected, but the session is resumed 
in the same time frame (sessions are currently not explicitly killed on rejected auths).

CONTRIBUTIONS WELCOME! If you are willing to help, just open a PR or contact me via bug system or simon.tretter@hokify.com.

## Motivation

### Why not Freeradius?

There are several reasons why I started implementing this radius server in node js. We are using
freeradius right now, but have several issues which are hard to tackle due to the reason that freeradius
is a complex software and supports many uses cases. It is also written in C++ and uses threads behind the scene.
Therefore it's not easy to extend or modify it, or even bring new feature in.
The idea of this project is to make a super simple node radius server, which is async by default. No complex
thread handling, no other fancy thing. The basic goal is to make WPA2 authenticiation easy again.

### 802.1x protocol in node

Another motivation is that it is very exciting to see how wireless protocols have evolved, and see
how a implementation like TTLS works.

### Few alternatives (only non-free ones like Jumpcloud...)

Furthermore there are few alternatives out there, e.g. jumpcloud is non-free and I couldn't find many others.

### Vision

As soon as I understood the TTLS PAP Tunnel approach, I had this vision of making Wlan Authentification easy
for everyone. Why limit it to something "complex" like LDAP and co. This library aims to make it easy for everyone
to implement either their own authentication mechanismus (e.g. against a database), or provides some mechansimns
out of the box (e.g. imap, static, ldap,..).

