const test = require('brittle')
const sodium = require('..')

test('crypto_shorthash', function (t) {
  const out = Buffer.alloc(sodium.crypto_shorthash_BYTES)
  const inp = Buffer.from('Hej, Verden!')
  const key = Buffer.alloc(sodium.crypto_shorthash_KEYBYTES)

  t.exception.all(function () {
    sodium.crypto_shorthash(Buffer.alloc(0), inp)
  }, 'throws on bad input')

  sodium.crypto_shorthash(out, inp, key)

  const result = '6a29984f782e684e'
  t.alike(out.toString('hex'), result, 'hashed the string')
})
