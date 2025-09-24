const test = require('brittle')
const sodium = require('../')
const vectors = require('./fixtures/pbkdf2.json')

test('basic', async (t) => {
  const password = Buffer.from('password')
  const salt = Buffer.from('salt')

  const output = Buffer.alloc(256)

  await sodium.extension_pbkdf2_sha512(output, password, salt, 1000, 256)

  t.unlike(output, Buffer.alloc(256))

  try {
    // output is too small
    const small = output.subarray(2)
    sodium.extension_pbkdf2_sha512(small, password, salt, 1000, 256)
    t.fail()
  } catch (e) {
    t.pass()
  }

  const big = Buffer.alloc(300)
  sodium.extension_pbkdf2_sha512(big, password, salt, 1000, 256)

  t.alike(big.subarray(0, 256), output)

  t.is(sodium.extension_pbkdf2_sha512_SALTBYTES, 16)
  t.is(sodium.extension_pbkdf2_sha512_HASHBYTES, 64)
  t.is(sodium.extension_pbkdf2_sha512_ITERATIONS_MIN, 1)
  t.is(sodium.extension_pbkdf2_sha512_BYTES_MAX, 0x3fffffffc0)
})

test('vectors', { timeout: 0 }, async (t) => {
  for (const v of vectors) {
    const password = Buffer.from(v.P)
    const salt = Buffer.from(v.S)
    const iterations = v.c
    const length = v.dkLen
    const output = Buffer.alloc(length)

    await sodium.extension_pbkdf2_sha512(
      output,
      password,
      salt,
      iterations,
      length
    )

    t.alike(output.toString('hex'), v.pbkdf2_hmac_sha512)
  }
})
