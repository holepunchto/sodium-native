const test = require('brittle')
const sodium = require('..')
const { isBare } = require('which-runtime')

/* benchmark call counts */
let N = {
  hash_calls: 92e6,
  verify_calls: 2e6,
  unseal_calls: 4e5,
  hash_batch_len: 4096,
  hash_batch_calls: 1e5
}

/* CI call counts */
N = {
  ...N,
  hash_calls: 2e5,
  verify_calls: 2e5,
  unseal_calls: 1e5, // 2xunseal per loop
  hash_batch_calls: 2e5
}

test('bench: crypto_generichash', { skip: !isBare }, t => {
  const buf = Buffer.alloc(1024).fill(0xAA)
  const out = Buffer.alloc(sodium.crypto_generichash_BYTES)
  const start = Date.now()
  for (let i = 0; i < N.hash_calls; i++) {
    sodium.crypto_generichash(out, buf)
  }
  const ms = Date.now() - start
  t.comment('ms', ms)
})

test('bench: crypto_sign_verify_detached', { skip: !isBare }, function (t) {
  const fixtures = require('./fixtures/crypto_sign.json')

  const publicKey = new Uint8Array(fixtures[0][1])
  const message = new Uint8Array(fixtures[0][3])
  const signature = new Uint8Array(fixtures[0][2])

  const start = Date.now()

  for (let i = 0; i < N.verify_calls; i++) {
    const valid = sodium.crypto_sign_verify_detached(signature, message, publicKey)
    if (!valid) throw new Error('Unexpected verification failure')
  }

  const ms = Date.now() - start
  t.comment('ms', ms)
})

test('bench: crypto_box_unseal', { skip: !isBare }, function (t) {
  const pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)

  sodium.crypto_box_keypair(pk, sk)

  const pk2 = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  const sk2 = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)

  sodium.crypto_box_keypair(pk2, sk2)

  const message = Buffer.from('Hello, sealed World!')
  const cipher = Buffer.alloc(message.length + sodium.crypto_box_SEALBYTES)

  sodium.crypto_box_seal(cipher, message, pk)
  t.not(cipher, message, 'message encrypted')
  t.not(cipher, Buffer.alloc(cipher.length), 'not blank')

  const plain = Buffer.alloc(cipher.length - sodium.crypto_box_SEALBYTES)

  const start = Date.now()

  for (let i = 0; i < N.unseal_calls; i++) {
    let success = sodium.crypto_box_seal_open(plain, cipher, pk2, sk2)
    if (success) throw new Error('Unexpected decryption occured')

    success = sodium.crypto_box_seal_open(plain, cipher, pk, sk)
    if (!success) throw new Error('Unexpected decryption failure')
  }

  const ms = Date.now() - start
  t.comment('ms', ms)
})

test('bench: crypto_generichash_batch', { skip: !isBare }, t => {
  const buf = Buffer.from('Hej, Verden')
  const batch = []
  for (let i = 0; i < N.hash_batch_len; i++) batch.push(buf)

  const out = Buffer.alloc(sodium.crypto_generichash_BYTES)
  const start = Date.now()
  for (let i = 0; i < N.hash_batch_calls; i++) {
    sodium.crypto_generichash_batch(out, batch)
  }

  const ms = Date.now() - start
  t.comment('ms', ms)
})
