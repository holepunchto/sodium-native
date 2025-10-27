const test = require('brittle')
const sodium = require('..')

test('crypto_hash_sha256', function (t) {
  const out = Buffer.alloc(sodium.crypto_hash_sha256_BYTES)
  const inp = Buffer.from('Hej, Verden!')

  t.exception.all(function () {
    sodium.crypto_hash(Buffer.alloc(0), inp)
  }, 'throws on bad input')

  sodium.crypto_hash_sha256(out, inp)

  const result =
    'f0704b1e832b05d01223952fb2512181af4f843ce7bb6b443afd5ea028010e6c'
  t.alike(out.toString('hex'), result, 'hashed the string')
})

test('crypto_hash_sha256_state', function (t) {
  const state = Buffer.alloc(sodium.crypto_hash_sha256_STATEBYTES)
  sodium.crypto_hash_sha256_init(state)

  const buf = Buffer.from('Hej, Verden!')

  for (let i = 0; i < 10; i++) sodium.crypto_hash_sha256_update(state, buf)

  const out = Buffer.alloc(sodium.crypto_hash_sha256_BYTES)
  sodium.crypto_hash_sha256_final(state, out)

  const result =
    '14207db33c6ac7d39ca5fe0e74432fa7a2ed15caf7f6ab5ef68d24017a899974'
  t.alike(out.toString('hex'), result, 'hashed the string')
})
