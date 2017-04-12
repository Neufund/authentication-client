/* eslint import/no-extraneous-dependencies: ["error", {"devDependencies": true}]*/
/* eslint-disable no-underscore-dangle,new-cap */
import 'babel-polyfill';
import chai from 'chai';
import dirtyChai from 'dirty-chai';
import faker from 'faker';
import sinon from 'sinon';
import { server } from 'jsrp';
import Authenticator from '../src/index';

const expect = chai.expect;
chai.use(dirtyChai);

const API_URL = 'fake url';

async function register(email, key) {
  const authenticator = new Authenticator(API_URL);
  const { salt, verifier } = await authenticator._srpRegister(email, key);
  const srpServer = new server();
  await new Promise(resolve => srpServer.init({ salt, verifier }, resolve));
  return { authenticator, srpServer, salt };
}

describe('Authenticator', () => {
  const email = faker.internet.email();
  const password = faker.internet.password();
  const kdfSalt = Authenticator._generateSalt();

  describe('#_srpCheckServer', () => {
    it('checks the server proof', async () => {
      const key = await Authenticator._scrypt(password, kdfSalt);
      const { authenticator, srpServer, salt } = await register(email, key);
      const { clientPublicKey, clientProof } =
        await authenticator._srpLogin(email, key, salt, srpServer.getPublicKey());
      srpServer.setClientPublicKey(clientPublicKey);
      srpServer.checkClientProof(clientProof);
      const serverProof = srpServer.getProof();
      expect(authenticator._srpCheckServer(serverProof)).to.be.true();
    });
  });

  describe('#_srpLogin', () => {
    it('should return correct clientPublicKey and clientProof', async () => {
      const key = await Authenticator._scrypt(password, kdfSalt);
      const { authenticator, srpServer, salt } = await register(email, key);
      const { clientPublicKey, clientProof } =
        await authenticator._srpLogin(email, key, salt, srpServer.getPublicKey());
      srpServer.setClientPublicKey(clientPublicKey);
      expect(srpServer.checkClientProof(clientProof)).to.be.true();
    });
  });

  describe('#_srpRegister', async () => {
    it('should return salt and verifier', async () => {
      const key = await Authenticator._scrypt(password, kdfSalt);
      const authenticator = new Authenticator(API_URL);
      const { salt, verifier } = await authenticator._srpRegister(email, key);
      expect(salt).to.have.lengthOf(64);
      expect(salt).to.not.equal(kdfSalt);
      expect(verifier).to.be.a('string');
    });
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
    it('generates random salt', async () => {
      const salt1 = new Authenticator._generateSalt();
      const salt2 = new Authenticator._generateSalt();
      expect(salt1).to.have.lengthOf(32);
      expect(salt2).to.have.lengthOf(32);
      expect(salt1).to.not.equal(salt2);
    });
  });

  describe('#register', () => {
    it('submits correct signup request', async () => {
      const secret = 'totpSecret';
      const authenticator = new Authenticator(API_URL);
      const requestStub = sinon.stub();
      authenticator._request = requestStub;
      requestStub.resolves({ text: () => (new Promise(resolve => resolve(secret))) });
      const totpSecret = await authenticator.register(email, password, 'captcha');
      expect(totpSecret).to.be.equal(secret);
      expect(requestStub.callCount).to.be.equal(1);
      const args = requestStub.firstCall.args;
      expect(args[0]).to.be.equal('/api/signup');
      const payload = args[1];
      expect(payload).to.not.have.property('password');
      expect(payload).to.have.property('email', email);
      expect(payload).to.have.property('captcha', 'captcha');
      expect(payload).to.have.property('kdfSalt');
      expect(payload).to.have.property('srpSalt');
      expect(payload).to.have.property('srpVerifier');
    });
  });
});
