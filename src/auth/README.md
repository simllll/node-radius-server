# Authentications

## Google LDAP

google ldap optimized authenticiation implementaiton

```typescript
interface IGoogleLDAPAuthOptions {
    /** base DN
     *  e.g. 'dc=hokify,dc=com', */
    base: string;
    tls: {
        keyFile: string;
        certFile: string;
    };
    /** tls options
     * e.g. {
            key: fs.readFileSync('ldap.gsuite.key'),
            cert: fs.readFileSync('ldap.gsuite.crt')
        } */
    tlsOptions?: tls.TlsOptions;
  }
```

Example

```js
c = {
	// GoogleLDAPAuth (optimized for google auth)
	authentication: 'GoogleLDAPAuth',
	authenticationOptions: {
		base: 'dc=hokify,dc=com',
		tls: {
            keyFile: 'ldap.gsuite.key',
            certFile: 'ldap.gsuite.crt'
        }
	}
};
```

## LDAP

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

	tls: {
		keyFile: string;
		certFile: string;
	};
	/** tls options
	 * e.g. {
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
            servername: 'ldap.google.com'
        },
        tls: {
            keyFile: 'ldap.gsuite.key',
            certFile: 'ldap.gsuite.crt'
        }
	}
};
```

## IMAP

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
};
```

## SMTP

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
};
```

## Static Auth

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
};
```


## HTTP Post Auth

http authenticiation via http post request

```typescript
interface IStaticAuthOtions {
	url: string; // url to send a post request with username and password 
}
```

Example

```js
c = {
	authentication: 'HTTPAuth',
	authenticationOptions: {
		url: 'https://my-website.com/api/backend-login'
	}
};
```
