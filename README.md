Basic RADIUS Server for node.js for Google LDAP Service and WPA2 Enteprise WLAN Authentification.
* Only implements LDAP as Authentification Backend
* Only WPA TTLS implemented (as this is the only one that works with Google LDAP Service)

## Known Issues / Disclaimer

This is a first implementation draft, which is currently NOT WORKING:

There is still one major issue left to get things going:
https://github.com/nodejs/node/issues/31802
that's why it's currently not possible to calculate MS-MPPE-Send-Key and MS-MPPE-Recv-Key.

* PAP / CHAP RFC not found to implement this correctly
* Project needs more structure and interfaces to extend it more easily in the future (make a full radius server out of it ;)?)
* No package queuing or any kind of respsecting the MTU size
* a lot of bugs

CONTRIBUTIONS WELCOME!

## Installation

    npm install
    npm run build

## Introduction

This app provides a radius server to authenticate against google's SLDAP service. To get this running
 you need:
 1.) Running LDAP Service (E.g. Google Suite Enterprise or Gloud Identity Premium)
 2.) Use stunnel to connect to the LDAP service and connect this app to the stunnel (I didn't get the client ldap authentication working in here yet)
 3.) Install a SSL certificate (e.g. self signed via npm run create-certificate)
 4.) Install und build server: npm install && npm run build
 5.) Start server node dist/app.ts --secret {RADIUS secret} --baseDN dc=hokify,dc=com
 
 
## Usage

You need to specify at least a radius password and the base DN for LDAP:

	node dist/app.ts --secret {RADIUS secret} --baseDN dc=hokify,dc=com

