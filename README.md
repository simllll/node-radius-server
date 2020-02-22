Basic RADIUS Server for node.js for Google LDAP Service and WPA2 Enteprise WLAN Authentification.

- supports LDAP Authentification Backend
- supports WPA2 Entprise (TTLS over PAP)

Protect your WIFI access with a username and password by a credential provider you already use!

## Known Issues / Disclaimer

This is a first implementation draft, which is currently only working with a nodejs fork (see https://github.com/nodejs/node/pull/31814).

- PAP / CHAP RFC not found to implement this correctly
- a lot of bugs

CONTRIBUTIONS WELCOME! If you are willing to help, just open a PR or contact me via bug system or simon.tretter@hokify.com.

## Installation

    npm install
    npm run build

## Introduction

This app provides a radius server to authenticate against google's SLDAP service. To get this running
you need:

1.  Running LDAP Service (E.g. Google Suite Enterprise or Gloud Identity Premium)
2.  Optional: Create your own SSL certificate (e.g. self signed via npm run create-certificate)
3.  Check config.js and adapt to your needs

- configure authentication (passport config), e.g. for LDAP

```js
var config = {
	// ....
	authentication: 'ldap',
	authenticationOptions: {
		url: 'ldap://127.0.0.1:1636',
		base: 'dc=hokify,dc=com'
	}
};
```

- set radius secret

4.  Install und build server: npm install && npm run build
5.  Start server "npm run start"

## Authentications

right now only one simple ldap implementation is done,
the idea is though to use [passport.js](http://www.passportjs.org/) as authentication provider,
therefore it would be possible to use the radius server with your email provider authentication or any
other auth mechanismus you use (well everything with no 2factor or anything else that requries an extra step).

## Usage

You need to specify at least a radius password and the base DN for LDAP:

    npm run start
