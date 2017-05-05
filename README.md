# authentication-client [![Build Status](https://travis-ci.org/Neufund/authentication-client.svg)](https://travis-ci.org/Neufund/authentication-client)

[![Greenkeeper badge](https://badges.greenkeeper.io/Neufund/authentication-client.svg)](https://greenkeeper.io/)
Client side library for the [authentication-server](https://github.com/Neufund/authentication-server)

## Example usage

### Registration
```javascript
const API_URL = 'http://localhost:3000';
const authenticator = new Authenticator(API_URL);
const otpSecret = await authenticator.register(email, password, captcha);
// Register otpSecret somewhere (e.g. show QR code for Google authenticator)
```

### Login
```javascript
const API_URL = 'http://localhost:3000';
const authenticator = new Authenticator(API_URL);
// Ask client for otpToken (2FA)
const jwt = await authenticator.login(email, password, otpToken);
// Use jwt to login
```

## Install deps
    yarn

## Run tests
    yarn test