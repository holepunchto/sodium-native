const test = require('brittle')
const sodium = require('..')

const _e = 1e2
/* call counts */
const N = {
  hash_calls: 1 * _e,
  verify_calls: 1 * _e,
  unseal_calls: 1 * _e, // 2xunseal per loop
  hash_batch_len: 64,
  hash_batch_calls: 1 * _e,
  stream_xor_calls: 1 * _e,
  stream_xchacha20_calls: 1 * _e // 2 calls per loop
}

test('fastcall: crypto_generichash', t => {
  const buf = Buffer.alloc(1024).fill(0xAA)
  const out = Buffer.alloc(sodium.crypto_generichash_BYTES)
  const bpush = benchmark(t)

  for (let i = 0; i < N.hash_calls; i++) {
    sodium.crypto_generichash(out, buf)
    bpush(1)
  }

  bpush(-1)
})

test('fastcall: crypto_sign_verify_detached', function (t) {
  const fixtures = require('./fixtures/crypto_sign.json')

  const publicKey = new Uint8Array(fixtures[0][1])
  const message = new Uint8Array(fixtures[0][3])
  const signature = new Uint8Array(fixtures[0][2])

  const bpush = benchmark(t)

  for (let i = 0; i < N.verify_calls; i++) {
    const valid = sodium.crypto_sign_verify_detached(signature, message, publicKey)
    if (!valid) throw new Error('Unexpected verification failure')
    bpush(1)
  }

  bpush(-1)
})

test('fastcall: crypto_box_unseal', function (t) {
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

  const bpush = benchmark(t)

  for (let i = 0; i < N.unseal_calls; i++) {
    let success = sodium.crypto_box_seal_open(plain, cipher, pk2, sk2)
    if (success) throw new Error('Unexpected decryption occured')

    success = sodium.crypto_box_seal_open(plain, cipher, pk, sk)
    if (!success) throw new Error('Unexpected decryption failure')
    bpush(2)
  }

  bpush(-1)
})

test('fastcall: crypto_generichash_batch', t => {
  const buf = Buffer.from('Hej, Verden')
  const batch = []
  for (let i = 0; i < N.hash_batch_len; i++) batch.push(buf)

  const out = Buffer.alloc(sodium.crypto_generichash_BYTES)

  const bpush = benchmark(t)

  for (let i = 0; i < N.hash_batch_calls; i++) {
    sodium.crypto_generichash_batch(out, batch)
    bpush(batch.length)
  }

  bpush(-1)
})

test('fastcall: crypto_stream_xor', t => {
  const message = Buffer.alloc(4096).fill(0xaa)
  const plain = Buffer.alloc(4096).fill(0xaa)
  const nonce = random(sodium.crypto_stream_NONCEBYTES)
  const key = random(sodium.crypto_stream_KEYBYTES)

  const bpush = benchmark(t)

  for (let i = 0; i < N.stream_xor_calls; i++) {
    sodium.crypto_stream_xor(message, message, nonce, key)
    if (message.equals(plain)) throw new Error('encryption failed')

    sodium.crypto_stream_xor(message, message, nonce, key)
    if (!message.equals(plain)) throw new Error('decryption failed')
    bpush(2)
  }

  bpush(-1)

  function random (n) {
    const buf = Buffer.alloc(n)
    sodium.randombytes_buf(buf)
    return buf
  }
})

test('fastcall: crypto_secretstream_xchacha20poly1305_push & pull', t => {
  const {
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE: TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_ABYTES: ABYTES,
    crypto_secretstream_xchacha20poly1305_STATEBYTES: STATEBYTES,
    crypto_secretstream_xchacha20poly1305_HEADERBYTES: HEADERBYTES,
    crypto_secretstream_xchacha20poly1305_KEYBYTES: KEYBYTES,
    crypto_secretstream_xchacha20poly1305_TAGBYTES: TAGBYTES
  } = sodium

  const header = Buffer.alloc(HEADERBYTES)
  const key = Buffer.alloc(KEYBYTES)
  const tag = Buffer.alloc(TAGBYTES, 0xdb)

  const adIn = Buffer.alloc(sodium.randombytes_uniform(100)) // additional data
  const adOut = Buffer.alloc(adIn.byteLength)

  sodium.crypto_secretstream_xchacha20poly1305_keygen(key)

  const stateEnc = Buffer.alloc(STATEBYTES)
  sodium.crypto_secretstream_xchacha20poly1305_init_push(stateEnc, header, key)

  const stateDec = Buffer.alloc(STATEBYTES)
  sodium.crypto_secretstream_xchacha20poly1305_init_pull(stateDec, header, key)

  const message = Buffer.alloc(1024, 0xaa)
  const cipher = Buffer.alloc(message.byteLength + ABYTES)
  const plain = Buffer.alloc(message.byteLength)

  const bpush = benchmark(t)

  for (let i = 0; i < N.stream_xchacha20_calls; i++) {
    let ret = sodium.crypto_secretstream_xchacha20poly1305_push(stateEnc, cipher, message, adIn, TAG_MESSAGE)
    if (ret !== message.byteLength + ABYTES) t.fail('invalid amount written')

    ret = sodium.crypto_secretstream_xchacha20poly1305_pull(stateDec, plain, tag, cipher, adOut)

    if (ret !== cipher.byteLength - ABYTES) t.fail('invalid amount read')
    if (tag[0] !== TAG_MESSAGE) t.fail('bad tag decoded')
    if (!message.equals(plain)) t.fail('decryption failed')
    if (!adOut.equals(adIn)) t.fail('additional data mismatch')

    bpush(2)
  }

  bpush(-1)
})

function benchmark (t, interval = 2000) {
  let prev
  const start = prev = Date.now()
  let n = 0
  let total = n

  return function measure (qty = 1) {
    const now = Date.now()
    const delta = now - prev

    if (qty > 0) {
      n += qty
      total += qty
    }

    if ((interval && interval < delta) || qty < 0) {
      const ops = (n / delta) * 1000
      const runtime = now - start
      const avg = (total / runtime) * 1000
      t.comment('ops', ops.toExponential(2), 'avg', Math.round(avg), 'total', total, 'runtime', runtime)
      prev = now
      n = 0
    }
  }
}
