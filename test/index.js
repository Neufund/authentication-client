/* eslint import/no-extraneous-dependencies: ["error", {"devDependencies": true}]*/
/* eslint-disable no-underscore-dangle */
import 'babel-polyfill';
import chai from 'chai';
import Authenticator from '../src/index';

const expect = chai.expect;

describe('Authenticator', () => {
  describe('#_srpCheckServer', () => {

  });
  describe('#_srpLogin', () => {

  });
  describe('#_srpRegister', () => {

  });
  describe('#_scrypt', () => {
    const hex = (str) => {
      const buf = Buffer.from(str, 'hex');
      const r = new Uint8Array(buf.length);
      for (let i = 0; i < buf.length; i += 1) {
        r[i] = buf[i];
      }
      return r;
    };

    it('should match the test vectors', async () => {
      const key = await Authenticator._scrypt('mypassword', 'saltysalt');
      const result = hex('5012b74fca8ec8a4a0a62ffdeeee959d');
      expect(key).to.be.deep.equal(result);
    });
  });
  describe('#_generateSalt', () => {

  });
  describe('#login', () => {

  });
  describe('#register', () => {

  });
});