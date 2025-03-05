const test = require('brittle')
const sodium = require('..')
const { isBare } = require('which-runtime')

test('crypto_stream', function (t) {
  const buf = Buffer.alloc(50)
  const nonce = random(sodium.crypto_stream_NONCEBYTES)
  const key = random(sodium.crypto_stream_KEYBYTES)

  sodium.crypto_stream(buf, nonce, key)

  t.not(buf, Buffer.alloc(50), 'contains noise now')
  const copy = Buffer.from(buf.toString('hex'), 'hex')

  sodium.crypto_stream(buf, nonce, key)
  t.alike(buf, copy, 'predictable from nonce, key')
})

test('crypto_stream_xor', function (t) {
  const message = Buffer.from('Hello, World!')
  const nonce = random(sodium.crypto_stream_NONCEBYTES)
  const key = random(sodium.crypto_stream_KEYBYTES)

  sodium.crypto_stream_xor(message, message, nonce, key)

  t.not(message, Buffer.from('Hello, World!'), 'encrypted')

  sodium.crypto_stream_xor(message, message, nonce, key)

  t.alike(message, Buffer.from('Hello, World!'), 'decrypted')
})

test('crypto_stream_xor state', function (t) {
  const message = Buffer.from('Hello, world!')
  const nonce = random(sodium.crypto_stream_NONCEBYTES)
  const key = random(sodium.crypto_stream_KEYBYTES)

  const out = Buffer.alloc(message.length)

  const state = Buffer.alloc(sodium.crypto_stream_xor_STATEBYTES)
  sodium.crypto_stream_xor_init(state, nonce, key)

  for (let i = 0; i < message.length; i++) {
    sodium.crypto_stream_xor_update(state, out.slice(i, i + 1), message.slice(i, i + 1))
  }

  sodium.crypto_stream_xor_final(state)
  sodium.crypto_stream_xor(out, out, nonce, key)
  t.alike(out, message, 'decrypted')
})

test('crypto_stream_xor state with empty buffers', function (t) {
  const message = Buffer.from('Hello, world!')
  const nonce = random(sodium.crypto_stream_NONCEBYTES)
  const key = random(sodium.crypto_stream_KEYBYTES)

  const out = Buffer.alloc(message.length)

  const state = Buffer.alloc(sodium.crypto_stream_xor_STATEBYTES)
  sodium.crypto_stream_xor_init(state, nonce, key)

  sodium.crypto_stream_xor_update(state, Buffer.alloc(0), Buffer.alloc(0))

  for (let i = 0; i < message.length; i++) {
    sodium.crypto_stream_xor_update(state, out.slice(i, i + 1), message.slice(i, i + 1))
    sodium.crypto_stream_xor_update(state, Buffer.alloc(0), Buffer.alloc(0))
  }

  sodium.crypto_stream_xor_final(state)
  sodium.crypto_stream_xor(out, out, nonce, key)
  t.alike(out, message, 'decrypted')
})

test('crypto_stream_xor state long stream', function (t) {
  const nonce = random(sodium.crypto_stream_NONCEBYTES)
  const key = random(sodium.crypto_stream_KEYBYTES)

  const encState = Buffer.alloc(sodium.crypto_stream_xor_STATEBYTES)
  const decState = Buffer.alloc(sodium.crypto_stream_xor_STATEBYTES)

  sodium.crypto_stream_xor_init(encState, nonce, key)
  sodium.crypto_stream_xor_init(decState, nonce, key)
  const plain = []
  const encrypted = []
  const decrypted = []

  for (let i = 0; i < 1000; i++) {
    const next = random(61)
    plain.push(next)

    const enc = Buffer.alloc(61)
    sodium.crypto_stream_xor_update(encState, enc, next)
    encrypted.push(enc)

    const dec = Buffer.alloc(61)
    sodium.crypto_stream_xor_update(decState, dec, enc)
    decrypted.push(dec)
  }

  const enc2 = Buffer.alloc(1000 * 61)
  sodium.crypto_stream_xor(enc2, Buffer.concat(plain), nonce, key)

  t.alike(Buffer.concat(encrypted), enc2, 'same as encrypting all at once')
  t.alike(Buffer.concat(decrypted), Buffer.concat(plain), 'decrypts')
})

test('crypto_stream_xor state long stream (random chunks)', function (t) {
  const nonce = random(sodium.crypto_stream_NONCEBYTES)
  const key = random(sodium.crypto_stream_KEYBYTES)

  const encState = Buffer.alloc(sodium.crypto_stream_xor_STATEBYTES)
  const decState = Buffer.alloc(sodium.crypto_stream_xor_STATEBYTES)

  sodium.crypto_stream_xor_init(encState, nonce, key)
  sodium.crypto_stream_xor_init(decState, nonce, key)
  const plain = []
  const encrypted = []
  const decrypted = []

  for (let i = 0; i < 10000; i++) {
    const len = Math.floor(Math.random() * 256)
    const next = random(len)
    plain.push(next)

    const enc = Buffer.alloc(len)
    sodium.crypto_stream_xor_update(encState, enc, next)
    encrypted.push(enc)

    const dec = Buffer.alloc(len)
    sodium.crypto_stream_xor_update(decState, dec, enc)
    decrypted.push(dec)
  }

  const enc2 = Buffer.alloc(Buffer.concat(plain).length)
  sodium.crypto_stream_xor(enc2, Buffer.concat(plain), nonce, key)

  t.alike(Buffer.concat(encrypted), enc2, 'same as encrypting all at once')
  t.alike(Buffer.concat(decrypted), Buffer.concat(plain), 'decrypts')
})

test('crypto_stream_xor state long stream (random chunks) with empty buffers', function (t) {
  const nonce = random(sodium.crypto_stream_NONCEBYTES)
  const key = random(sodium.crypto_stream_KEYBYTES)

  const encState = Buffer.alloc(sodium.crypto_stream_xor_STATEBYTES)
  const decState = Buffer.alloc(sodium.crypto_stream_xor_STATEBYTES)

  sodium.crypto_stream_xor_init(encState, nonce, key)
  sodium.crypto_stream_xor_init(decState, nonce, key)
  const plain = []
  const encrypted = []
  const decrypted = []

  for (let i = 0; i < 10000; i++) {
    const len = Math.floor(Math.random() * 256)
    const next = random(len)
    plain.push(next)

    sodium.crypto_stream_xor_update(encState, Buffer.alloc(0), Buffer.alloc(0))

    const enc = Buffer.alloc(len)
    sodium.crypto_stream_xor_update(encState, enc, next)
    encrypted.push(enc)

    const dec = Buffer.alloc(len)
    sodium.crypto_stream_xor_update(decState, dec, enc)
    decrypted.push(dec)
    sodium.crypto_stream_xor_update(decState, Buffer.alloc(0), Buffer.alloc(0))
  }

  const enc2 = Buffer.alloc(Buffer.concat(plain).length)
  sodium.crypto_stream_xor(enc2, Buffer.concat(plain), nonce, key)

  t.alike(Buffer.concat(encrypted), enc2, 'same as encrypting all at once')
  t.alike(Buffer.concat(decrypted), Buffer.concat(plain), 'decrypts')
})

test('crypto_stream_xor state after GC', { skip: isBare }, function (t) {
  const message = Buffer.from('Hello, world!')
  let nonce = random(sodium.crypto_stream_NONCEBYTES)
  let key = random(sodium.crypto_stream_KEYBYTES)

  const out = Buffer.alloc(message.length)

  const state = Buffer.alloc(sodium.crypto_stream_xor_STATEBYTES)
  sodium.crypto_stream_xor_init(state, nonce, key)

  const nonceCopy = Buffer.from(nonce.toString('hex'), 'hex')
  const keyCopy = Buffer.from(key.toString('hex'), 'hex')
  nonce = null
  key = null

  forceGC()

  for (let i = 0; i < message.length; i++) {
    sodium.crypto_stream_xor_update(state, out.slice(i, i + 1), message.slice(i, i + 1))
  }

  sodium.crypto_stream_xor_final(state)
  sodium.crypto_stream_xor(out, out, nonceCopy, keyCopy)
  t.alike(out, message, 'decrypted')
})

function random (n) {
  const buf = Buffer.alloc(n)
  sodium.randombytes_buf(buf)
  return buf
}

function forceGC () {
  require('v8').setFlagsFromString('--expose-gc')
  require('vm').runInNewContext('gc')()
}
