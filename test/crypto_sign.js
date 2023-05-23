const test = require('brittle')
const sodium = require('..')

test('crypto_sign_ed25519_sk_to_pk', function (t) {
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const pke = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_keypair(pk, sk)
  sodium.crypto_sign_ed25519_sk_to_pk(pke, sk)

  t.ok(pk.equals(pke))
})

test('crypto_sign_seed_keypair', function (t) {
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  const seed = Buffer.alloc(sodium.crypto_sign_SEEDBYTES, 'lo')

  t.exception.all(function () {
    sodium.crypto_sign_seed_keypair()
  }, 'should validate input')

  t.exception.all(function () {
    sodium.crypto_sign_seed_keypair(Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0))
  }, 'should validate input length')

  sodium.crypto_sign_seed_keypair(pk, sk, seed)

  const eSk = '6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f41eb5b4dba29b19e391d9a4d1a4a879b27958ff3734e10cfbf1f46d68f4d3038'
  const ePk = '41eb5b4dba29b19e391d9a4d1a4a879b27958ff3734e10cfbf1f46d68f4d3038'

  t.alike(pk.toString('hex'), ePk, 'seeded public key')
  t.alike(sk.toString('hex'), eSk, 'seeded secret key')
})

test('crypto_sign_keypair', function (t) {
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_keypair(pk, sk)

  t.not(pk, Buffer.alloc(pk.length), 'made public key')
  t.not(sk, Buffer.alloc(sk.length), 'made secret key')

  t.exception.all(function () {
    sodium.crypto_sign_keypair()
  }, 'should validate input')

  t.exception.all(function () {
    sodium.crypto_sign_keypair(Buffer.alloc(0), Buffer.alloc(0))
  }, 'should validate input length')
})

test('crypto_sign', function (t) {
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_keypair(pk, sk)

  const message = Buffer.from('Hello, World!')
  const signedMessage = Buffer.alloc(message.length + sodium.crypto_sign_BYTES)

  sodium.crypto_sign(signedMessage, message, sk)

  t.alike(signedMessage.slice(-message.length), message, 'contains message')

  const output = Buffer.alloc(message.length)

  t.absent(sodium.crypto_sign_open(output, Buffer.alloc(signedMessage.length), pk), 'was not signed')
  t.ok(sodium.crypto_sign_open(output, signedMessage, pk), 'was signed')

  t.alike(output, message, 'same message')
})

test('crypto_sign_detached', function (t) {
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_keypair(pk, sk)

  const message = Buffer.from('Hello, World!')
  const signature = Buffer.alloc(sodium.crypto_sign_BYTES)

  sodium.crypto_sign_detached(signature, message, sk)

  t.absent(sodium.crypto_sign_verify_detached(Buffer.concat([Buffer.alloc(1), signature]), message, pk), 'was not signed')
  t.ok(sodium.crypto_sign_verify_detached(signature, message, pk), 'was signed')
})
