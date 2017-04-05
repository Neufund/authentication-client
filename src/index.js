/* eslint new-cap: ["error", { "newIsCapExceptions": ["jsrp.client"] }] */
import scrypt from 'scrypt-async';
import jsrp from 'jsrp';
import randomBytes from 'randombytes';

class Authenticator {
  constructor(apiUrl) {
    this.apiUrl = apiUrl;
    this.srp = null;
  }

  async register(email, passphrase, captcha) {
    const scryptSalt = Authenticator.generateSalt();
    const key = await Authenticator.scrypt(passphrase, scryptSalt);
    const srp = await this.srpRegister(email, key);
    console.log({
      ...srp,
      email,
      scryptSalt,
      captcha,
    });
  }

  // async login(username, passphrase, otp) {}

  static generateSalt() {
    return randomBytes(32);
  }

  static async scrypt(passphrase, salt) {
    const parameters = {
      N: 16384, // about 100ms
      r: 8,
      p: 1,
      dkLen: 16,
      encoding: 'binary',
    };
    return new Promise(resolve =>
      scrypt(passphrase, salt, parameters, resolve));
  }

  async srpRegister(username, passphrase) {
    const parameters = {
      username,
      password: passphrase,
      length: 4096,
    };
    this.srp = new jsrp.client();
    await new Promise(resolve => this.srp.init(parameters, resolve));
    return new Promise((resolve, reject) =>
      this.srp.createVerifier(
        (err, result) => (err ? reject(err) : resolve(result)),
      ));
  }

  async srpLogin(username, passphrase, salt, pubKey) {
    const parameters = {
      username,
      password: passphrase,
      length: 4096,
    };
    this.srp = new jsrp.client();
    await new Promise(resolve => this.srp.init(parameters, resolve));
    this.srp.setSalt(salt);
    this.srp.setServerPublicKey(pubKey);
    return {
      pubKey: this.srp.getPublicKey(),
      proof: this.srp.getProof(),
    };
  }

  srpCheckServer(proof) {
    if (this.srp === null) {
      throw new Error('srpLogin needs to be called first');
    }
    return this.srp.checkServerProof(proof);
  }
}

export default Authenticator;
