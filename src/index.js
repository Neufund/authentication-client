import scrypt from 'scrypt-async'

export default class {
  constructor (apiUrl) {
    this.apiUrl = apiUrl
  }

  async login (username, passphrase, otp) {}

  async scrypt (passphrase, salt) {
    const parameters = {
      N: 16384, // about 100ms
      r: 8,
      p: 1,
      dkLen: 16,
      encoding: 'binary'
    }
    return new Promise(resolve =>
      scrypt(passphrase, salt, parameters, resolve))
  }
}
