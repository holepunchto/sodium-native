const test = require('brittle')
const sodium = require('..')

test('crypto_scalarmult_base', function (t) {
  const keys = keyPair()

  t.not(keys.secretKey, Buffer.alloc(keys.secretKey.length), 'secret key not blank')
  t.not(keys.publicKey, Buffer.alloc(keys.publicKey.length), 'public key not blank')
})

test('crypto_scalarmult', function (t) {
  const peer1 = keyPair()
  const peer2 = keyPair()

  t.not(peer1.secretKey, peer2.secretKey, 'diff secret keys')
  t.not(peer1.publicKey, peer2.publicKey, 'diff public keys')

  const shared1 = Buffer.alloc(sodium.crypto_scalarmult_BYTES)
  const shared2 = Buffer.alloc(sodium.crypto_scalarmult_BYTES)

  sodium.crypto_scalarmult(shared1, peer1.secretKey, peer2.publicKey)
  sodium.crypto_scalarmult(shared2, peer2.secretKey, peer1.publicKey)

  t.alike(shared1, shared2, 'same shared secret')
})

function keyPair () {
  const secretKey = Buffer.alloc(sodium.crypto_scalarmult_SCALARBYTES)
  sodium.randombytes_buf(secretKey)

  const publicKey = Buffer.alloc(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_scalarmult_base(publicKey, secretKey)

  return {
    publicKey,
    secretKey
  }
}
