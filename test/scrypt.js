import 'babel-polyfill'
import assert from 'assert'
import Authenticator from '../src/index.js'

const hex = str => {
  let buf = Buffer.from(str, 'hex')
  let r = new Uint8Array(buf.length)
  for (let i = 0; i < buf.length; i++) {
    r[i] = buf[i]
  }
  return r
}

describe('Scrypt', async () => {
  it('should match the test vectors', async () => {
    let auth = new Authenticator('/nop')
    let key = await auth.scrypt('mypassword', 'saltysalt')
    const result = hex('5012b74fca8ec8a4a0a62ffdeeee959d')
    assert.deepEqual(key, result)
  })
})
