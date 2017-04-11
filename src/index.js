/* eslint new-cap: ["error", {"newIsCapExceptions": ["jsrp.client"]}] */
/* eslint-disable no-underscore-dangle */
import scrypt from 'scrypt-async';
import jsrp from 'jsrp';
import randomBytes from 'randombytes';

const SCRYPT_PARAMETERS = {
  N: 16384, // about 100ms
  r: 8,
  p: 1,
  dkLen: 16,
  encoding: 'binary',
};
const SALT_LENGTH = 32;
const SRP_KEY_LENGTH = 4096;

/**
 * Class for communicating with the SRP authentication server
 * @see {@link https://github.com/Neufund/authentication-server|authentication-server}
 */
class Authenticator {
  /**
   * Creates Authenticator object from API url
   * @param {String} apiUrl - base URL of authentication-server
   * @param {Number} [keyLength=SRP_KEY_LENGTH] - SRP key length
   */
  constructor(apiUrl, keyLength = SRP_KEY_LENGTH) {
    this.apiUrl = apiUrl;
    this.keyLength = keyLength;
    this.srp = null;
  }

  /**
   * Registers the user
   * @param {String} email
   * @param {String} passphrase
   * @param {String} captcha - reCAPTCHA token
   * @return {Promise.<String>} - OneTimePasswordSecret
   */
  async register(email, passphrase, captcha) {
    const kdfSalt = Authenticator._generateSalt().toString('hex');
    const key = await Authenticator._scrypt(passphrase, kdfSalt);
    const { salt, verifier } = await this._srpRegister(email, key);
    return (await this._request('/api/signup', {
      email,
      captcha,
      kdfSalt,
      srpSalt: salt,
      srpVerifier: verifier,
    })).text();
  }

  /**
   * Logs in the user
   * @param {String} email
   * @param {String} passphrase
   * @param {String} timeBasedOneTimeToken
   * @return {Promise.<String>} - JSON Web Token
   */
  async login(email, passphrase, timeBasedOneTimeToken) {
    const { encryptedPart, srpSalt, kdfSalt, serverPublicKey } =
      await (await this._request('/api/login-data', { email })).json();
    const { clientProof, clientPublicKey } =
      await this._srpLogin(email, passphrase, srpSalt, kdfSalt, serverPublicKey);
    const { token, serverProof } = await (await this._request('/api/login', {
      clientProof,
      clientPublicKey,
      email,
      timeBasedOneTimeToken,
      encryptedPart,
    })).json();
    if (!this._srpCheckServer(serverProof)) {
      throw new Error('Wrong server proof');
    }
    return token;
  }

  /**
   * Generates random salt
   * @return {Uint8Array} - generated salt
   * @private
   */
  static _generateSalt() {
    return randomBytes(SALT_LENGTH);
  }

  /**
   * Password strengthening function
   * @param {String} passphrase
   * @param {String} salt
   * @return {Promise.<Uint8Array>} - derived key
   * @private
   */
  static async _scrypt(passphrase, salt) {
    return new Promise(resolve => scrypt(passphrase, salt, SCRYPT_PARAMETERS, resolve));
  }

  /**
   * Creates SRP verifier and salt from derived key
   * @param {String} email
   * @param {Uint8Array} key - derived key
   * @return {Promise.<{verifier, salt}>} - SRP verifier object
   * @private
   */
  async _srpRegister(email, key) {
    const parameters = {
      username: email,
      password: key,
      length: this.keyLength,
    };
    this.srp = new jsrp.client();
    await new Promise(resolve => this.srp.init(parameters, resolve));
    return new Promise((resolve, reject) =>
      this.srp.createVerifier(
        (err, result) => (err ? reject(err) : resolve(result)),
      ));
  }

  /**
   * Generates client proof and public key
   * @param {String} email
   * @param {String} passphrase
   * @param {String} srpSalt
   * @param {String} kdfSalt
   * @param {String} serverPublicKey
   * @return {Promise.<{clientPublicKey, clientProof}>}
   * @private
   */
  async _srpLogin(email, passphrase, srpSalt, kdfSalt, serverPublicKey) {
    const key = await Authenticator._scrypt(passphrase, kdfSalt);
    this.srp = new jsrp.client();
    await new Promise(resolve => this.srp.init({
      username: email,
      password: key,
      length: this.keyLength,
    }, resolve));
    this.srp.setSalt(srpSalt);
    this.srp.setServerPublicKey(serverPublicKey);
    return {
      clientPublicKey: this.srp.getPublicKey(),
      clientProof: this.srp.getProof(),
    };
  }

  /**
   * Checks server proof
   * @param {String} serverProof
   * @return {Boolean} if proof is OK
   * @private
   */
  _srpCheckServer(serverProof) {
    if (this.srp === null) {
      throw new Error('srpLogin needs to be called first');
    }
    return this.srp.checkServerProof(serverProof);
  }

  /**
   * Sends POST request to auth server
   * @param {String} path - API path
   * @param {Object} data - payload data
   * @return {*} - response promise
   * @private
   */
  _request(path, data) {
    return fetch(`${this.apiUrl}${path}`, {
      method: 'POST',
      headers: new Headers({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(data),
    });
  }
}

export default Authenticator;
