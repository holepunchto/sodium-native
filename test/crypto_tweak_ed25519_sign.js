const tape = require('tape')
const sodium = require('../')
const fixtures = require('./fixtures/crypto_tweak_ed25519_sign.js')

tape('crypto_tweak sign fixtures', t => {
  for (const f of fixtures) {
    const [sk, n, m, sig] = f.map(Buffer.from)

    const signature = Buffer.alloc(64)
    const scalar = Buffer.alloc(32)

    sodium.experimental_crypto_tweak_ed25519_sk_to_scalar(scalar, sk)
    t.same(scalar, n)

    sodium.experimental_crypto_tweak_ed25519_sign_detached(signature, m, n)
    t.same(signature, sig)
  }
  t.end()
})
