/* eslint-disable no-underscore-dangle */
import 'babel-polyfill';
import assert from 'assert';
import Authenticator from '../src/index';

const hex = (str) => {
  const buf = Buffer.from(str, 'hex');
  const r = new Uint8Array(buf.length);
  for (let i = 0; i < buf.length; i += 1) {
    r[i] = buf[i];
  }
  return r;
};

describe('Scrypt', async () => {
  it('should match the test vectors', async () => {
    const key = await Authenticator._scrypt('mypassword', 'saltysalt');
    const result = hex('5012b74fca8ec8a4a0a62ffdeeee959d');
    assert.deepEqual(key, result);
  });
});
