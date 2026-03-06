const assert = require('assert')
const binding = require('./binding')
const { isNode } = require('which-runtime')

const OPTIONAL = Buffer.from(new ArrayBuffer(0))

module.exports = exports = { ...binding }

// memory

exports.sodium_memzero = function (buf) {
  assert(ArrayBuffer.isView(buf), 'buf must be a typed array')

  binding.sodium_memzero(buf)
}

exports.sodium_mlock = function (buf) {
  assert(ArrayBuffer.isView(buf), 'buf must be a typed array')

  const res = binding.sodium_mlock(buf)

  if (res !== 0) throw new Error('memory lock failed')
}

exports.sodium_munlock = function (buf) {
  assert(ArrayBuffer.isView(buf), 'buf must be a typed array')

  const res = binding.sodium_munlock(buf)

  if (res !== 0) throw new Error('memory unlock failed')
}

exports.sodium_malloc = function (size) {
  assert(size >= 0, 'invalid size')

  const buf = Buffer.from(binding.sodium_malloc(size))
  buf.secure = true
  return buf
}

exports.sodium_free = function (buf) {
  if (!buf || !buf.secure) return

  binding.sodium_free(buf.buffer)
}

exports.sodium_mprotect_noaccess = function (buf) {
  const res = binding.sodium_mprotect_noaccess(buf.buffer)

  if (res !== 0) throw new Error('failed to lock buffer')
}

exports.sodium_mprotect_readonly = function (buf) {
  const res = binding.sodium_mprotect_readonly(buf.buffer)

  if (res !== 0) throw new Error('failed to unlock buffer')
}

exports.sodium_mprotect_readwrite = function (buf) {
  const res = binding.sodium_mprotect_readwrite(buf.buffer)

  if (res !== 0) throw new Error('failed to unlock buffer')
}

// crypto_randombytes

exports.randombytes_buf = function (buffer) {
  assert(ArrayBuffer.isView(buffer), 'buffer must be a typed array')

  binding.randombytes_buf(buffer.buffer, buffer.byteOffset, buffer.byteLength)
}

exports.randombytes_buf_deterministic = function (buffer, seed) {
  assert(ArrayBuffer.isView(buffer), 'buffer must be a typed array')
  assert(ArrayBuffer.isView(seed), 'seed must be a typed array')
  assert(
    seed.byteLength === binding.randombytes_SEEDBYTES,
    "seed must be 'randombytes_SEEDBYTES' bytes"
  )

  binding.randombytes_buf_deterministic(
    buffer.buffer,
    buffer.byteOffset,
    buffer.byteLength,

    seed.buffer,
    seed.byteOffset,
    seed.byteLength
  )
}

// sodium_helpers

exports.sodium_memcmp = function (a, b) {
  assert(ArrayBuffer.isView(a), 'a must be a typed array')
  assert(ArrayBuffer.isView(b), 'b must be a typed array')
  assert(a.byteLength === b.byteLength, 'buffers must be of same length')

  return binding.sodium_memcmp(a, b)
}

exports.sodium_add = function (a, b) {
  assert(ArrayBuffer.isView(a), 'a must be a typed array')
  assert(ArrayBuffer.isView(b), 'b must be a typed array')
  assert(a.byteLength === b.byteLength, 'buffers must be of same length')

  binding.sodium_add(a, b)
}

exports.sodium_sub = function (a, b) {
  assert(ArrayBuffer.isView(a), 'a must be a typed array')
  assert(ArrayBuffer.isView(b), 'b must be a typed array')
  assert(a.byteLength === b.byteLength, 'buffers must be of same length')

  binding.sodium_sub(a, b)
}

exports.sodium_compare = function (a, b) {
  assert(ArrayBuffer.isView(a), 'a must be a typed array')
  assert(ArrayBuffer.isView(b), 'b must be a typed array')
  assert(a.byteLength === b.byteLength, 'buffers must be of same length')

  return binding.sodium_compare(a, b)
}

exports.sodium_is_zero = function (buffer, length) {
  if (length === undefined) length = buffer.byteLength

  assert(ArrayBuffer.isView(buffer), 'buffer must be a typed array')
  assert(length >= 0 && length <= buffer.byteLength, 'invalid length')

  return binding.sodium_is_zero(buffer, length)
}

exports.sodium_pad = function (buffer, unpaddedBuflen, blockSize) {
  assert(ArrayBuffer.isView(buffer), 'buffer must be a typed array')
  assert(unpaddedBuflen <= buffer.byteLength, 'unpadded length cannot exceed buffer length')
  assert(blockSize <= buffer.byteLength, 'block size cannot exceed buffer length')
  assert(blockSize >= 1, 'block size must be at least 1 byte')
  assert(
    buffer.byteLength >= unpaddedBuflen + (blockSize - (unpaddedBuflen % blockSize)),
    'buf not long enough'
  )

  return binding.sodium_pad(buffer, unpaddedBuflen, blockSize)
}

exports.sodium_unpad = function (buffer, paddedBuflen, blockSize) {
  assert(ArrayBuffer.isView(buffer), 'buffer must be a typed array')
  assert(paddedBuflen <= buffer.byteLength, 'unpadded length cannot exceed buffer length')
  assert(blockSize <= buffer.byteLength, 'block size cannot exceed buffer length')
  assert(blockSize >= 1, 'block size must be at least 1 byte')

  return binding.sodium_unpad(buffer, paddedBuflen, blockSize)
}

// crypto_sign

exports.crypto_sign_keypair = function (pk, sk) {
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(ArrayBuffer.isView(sk), 'sk must be a typed array')
  assert(
    pk.byteLength === binding.crypto_sign_PUBLICKEYBYTES,
    "pk must be 'crypto_sign_PUBLICKEYBYTES' bytes"
  )
  assert(
    sk.byteLength === binding.crypto_sign_SECRETKEYBYTES,
    "sk must be 'crypto_sign_SECRETKEYBYTES' bytes"
  )

  const res = binding.crypto_sign_keypair(pk, sk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_sign_seed_keypair = function (pk, sk, seed) {
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(ArrayBuffer.isView(sk), 'sk must be a typed array')
  assert(ArrayBuffer.isView(seed), 'seed must be a typed array')
  assert(
    pk.byteLength === binding.crypto_sign_PUBLICKEYBYTES,
    "pk must be 'crypto_sign_PUBLICKEYBYTES' bytes"
  )
  assert(
    sk.byteLength === binding.crypto_sign_SECRETKEYBYTES,
    "sk must be 'crypto_sign_SECRETKEYBYTES' bytes"
  )
  assert(
    seed.byteLength === binding.crypto_sign_SEEDBYTES,
    "seed must be 'crypto_sign_SEEDBYTES' bytes"
  )

  const res = binding.crypto_sign_seed_keypair(pk, sk, seed)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_sign = function (sm, m, sk) {
  assert(ArrayBuffer.isView(sm), 'sm must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(sk), 'sk must be a typed array')
  assert(
    sm.byteLength === binding.crypto_sign_BYTES + m.byteLength,
    "sm must be 'm.byteLength + crypto_sign_BYTES' bytes"
  )
  assert(
    sk.byteLength === binding.crypto_sign_SECRETKEYBYTES,
    "sk must be 'crypto_sign_SECRETKEYBYTES' bytes"
  )

  const res = binding.crypto_sign(sm, m, sk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_sign_open = function (m, sm, pk) {
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(sm), 'sm must be a typed array')
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(
    sm.byteLength >= binding.crypto_sign_BYTES,
    "sm must be at least 'crypto_sign_BYTES' bytes"
  )
  assert(
    m.byteLength === sm.byteLength - binding.crypto_sign_BYTES,
    "m must be 'sm.byteLength - crypto_sign_BYTES' bytes"
  )
  assert(
    pk.byteLength === binding.crypto_sign_PUBLICKEYBYTES,
    "pk must be 'crypto_sign_PUBLICKEYBYTES' bytes"
  )

  const res = binding.crypto_sign_open(m, sm, pk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_sign_open = function (m, sm, pk) {
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(sm), 'sm must be a typed array')
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(
    sm.byteLength >= binding.crypto_sign_BYTES,
    "sm must be at least 'crypto_sign_BYTES' bytes"
  )
  assert(
    m.byteLength === sm.byteLength - binding.crypto_sign_BYTES,
    "m must be 'sm.byteLength - crypto_sign_BYTES' bytes"
  )
  assert(
    pk.byteLength === binding.crypto_sign_PUBLICKEYBYTES,
    "pk must be 'crypto_sign_PUBLICKEYBYTES' bytes"
  )

  return binding.crypto_sign_open(m, sm, pk)
}

exports.crypto_sign_detached = function (sig, m, sk) {
  assert(ArrayBuffer.isView(sig), 'sig must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(sk), 'sk must be a typed array')
  assert(sig.byteLength === binding.crypto_sign_BYTES, "sig must be 'crypto_sign_BYTES' bytes")
  assert(
    sk.byteLength === binding.crypto_sign_SECRETKEYBYTES,
    "sk must be 'crypto_sign_SECRETKEYBYTES' bytes"
  )

  const res = binding.crypto_sign_detached(sig, m, sk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_sign_verify_detached = function (sig, m, pk) {
  assert(ArrayBuffer.isView(sig), 'sig must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(
    sig.byteLength >= binding.crypto_sign_BYTES,
    "sig must be at least 'crypto_sign_BYTES' bytes"
  )
  assert(
    pk.byteLength === binding.crypto_sign_PUBLICKEYBYTES,
    "pk must be 'crypto_sign_PUBLICKEYBYTES' bytes"
  )

  return binding.crypto_sign_verify_detached(
    sig.buffer,
    sig.byteOffset,
    sig.byteLength,

    m.buffer,
    m.byteOffset,
    m.byteLength,

    pk.buffer,
    pk.byteOffset,
    pk.byteLength
  )
}

exports.crypto_sign_ed25519_sk_to_pk = function (pk, sk) {
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(ArrayBuffer.isView(sk), 'sk must be a typed array')
  assert(
    pk.byteLength === binding.crypto_sign_PUBLICKEYBYTES,
    "pk must be 'crypto_sign_PUBLICKEYBYTES' bytes"
  )
  assert(
    sk.byteLength === binding.crypto_sign_SECRETKEYBYTES,
    "sk must be 'crypto_sign_SECRETKEYBYTES' bytes"
  )

  const res = binding.crypto_sign_ed25519_sk_to_pk(pk, sk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_sign_ed25519_pk_to_curve25519 = function (x25519pk, ed25519pk) {
  assert(ArrayBuffer.isView(x25519pk), 'x25519pk must be a typed array')
  assert(ArrayBuffer.isView(ed25519pk), 'ed25519pk must be a typed array')
  assert(
    x25519pk.byteLength === binding.crypto_box_PUBLICKEYBYTES,
    "x25519pk must be 'crypto_box_PUBLICKEYBYTES' bytes"
  )
  assert(
    ed25519pk.byteLength === binding.crypto_sign_PUBLICKEYBYTES,
    "ed25519pk must be 'crypto_sign_PUBLICKEYBYTES' bytes"
  )

  const res = binding.crypto_sign_ed25519_pk_to_curve25519(x25519pk, ed25519pk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_sign_ed25519_sk_to_curve25519 = function (x25519sk, ed25519sk) {
  assert(ArrayBuffer.isView(x25519sk), 'x25519sk must be a typed array')
  assert(ArrayBuffer.isView(ed25519sk), 'ed25519sk must be a typed array')
  assert(
    x25519sk.byteLength === binding.crypto_box_SECRETKEYBYTES,
    "x25519sk must be 'crypto_box_SECRETKEYBYTES' bytes"
  )

  const edLen = ed25519sk.byteLength

  assert(
    edLen === binding.crypto_sign_SECRETKEYBYTES || edLen === binding.crypto_box_SECRETKEYBYTES,
    "ed25519sk must be 'crypto_sign_SECRETKEYBYTES' or 'crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES' bytes"
  )

  const res = binding.crypto_sign_ed25519_sk_to_curve25519(x25519sk, ed25519sk)

  if (res !== 0) throw new Error('status: ' + res)
}

// crypto_box

exports.crypto_box_keypair = function (pk, sk) {
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(
    pk.byteLength === binding.crypto_box_PUBLICKEYBYTES,
    "pk must be 'crypto_box_PUBLICKEYBYTES' bytes"
  )
  assert(ArrayBuffer.isView(sk), 'sk must be a typed array')
  assert(
    sk.byteLength === binding.crypto_box_SECRETKEYBYTES,
    "sk must be 'crypto_box_SECRETKEYBYTES' bytes"
  )

  const res = binding.crypto_box_keypair(pk, sk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_box_seed_keypair = function (pk, sk, seed) {
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(
    pk.byteLength === binding.crypto_box_PUBLICKEYBYTES,
    "pk must be 'crypto_box_PUBLICKEYBYTES' bytes"
  )
  assert(ArrayBuffer.isView(sk), 'sk must be a typed array')
  assert(
    sk.byteLength === binding.crypto_box_SECRETKEYBYTES,
    "sk must be 'crypto_box_SECRETKEYBYTES' bytes"
  )
  assert(ArrayBuffer.isView(seed), 'seed must be a typed array')
  assert(
    seed.byteLength === binding.crypto_box_SEEDBYTES,
    "seed must be 'crypto_box_SEEDBYTES' bytes"
  )

  const res = binding.crypto_box_seed_keypair(pk, sk, seed)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_box_easy = function (c, m, n, pk, sk) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(ArrayBuffer.isView(sk), 'sk must be a typed array')
  assert(
    c.byteLength === m.byteLength + exports.crypto_box_MACBYTES,
    "c must be 'm.byteLength + crypto_box_MACBYTES' bytes"
  )
  assert(n.byteLength === exports.crypto_box_NONCEBYTES, "n must be 'crypto_box_NONCEBYTES' bytes")
  assert(
    pk.byteLength === exports.crypto_box_PUBLICKEYBYTES,
    "pk must be 'crypto_box_PUBLICKEYBYTES' bytes"
  )
  assert(
    sk.byteLength === exports.crypto_box_SECRETKEYBYTES,
    "sk must be 'crypto_box_SECRETKEYBYTES' bytes"
  )

  const res = binding.crypto_box_easy(c, m, n, pk, sk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_box_detached = function (c, mac, m, n, pk, sk) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(mac), 'mac must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(ArrayBuffer.isView(sk), 'sk must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")
  assert(mac.byteLength === exports.crypto_box_MACBYTES, "mac must be 'crypto_box_MACBYTES' bytes")
  assert(n.byteLength === exports.crypto_box_NONCEBYTES, "n must be 'crypto_box_NONCEBYTES' bytes")
  assert(
    pk.byteLength === exports.crypto_box_PUBLICKEYBYTES,
    "pk must be 'crypto_box_PUBLICKEYBYTES' bytes"
  )
  assert(
    sk.byteLength === exports.crypto_box_SECRETKEYBYTES,
    "sk must be 'crypto_box_SECRETKEYBYTES' bytes"
  )

  const res = binding.crypto_box_detached(c, mac, m, n, pk, sk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_box_open_easy = function (m, c, n, pk, sk) {
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(ArrayBuffer.isView(sk), 'sk must be a typed array')
  assert(
    c.byteLength >= exports.crypto_box_MACBYTES,
    "c must be at least 'crypto_box_MACBYTES' bytes"
  )
  assert(
    m.byteLength === c.byteLength - exports.crypto_box_MACBYTES,
    "m must be 'c.byteLength - crypto_box_MACBYTES' bytes"
  )
  assert(n.byteLength === exports.crypto_box_NONCEBYTES, "n must be 'crypto_box_NONCEBYTES' bytes")
  assert(
    pk.byteLength === exports.crypto_box_PUBLICKEYBYTES,
    "pk must be 'crypto_box_PUBLICKEYBYTES' bytes"
  )
  assert(
    sk.byteLength === exports.crypto_box_SECRETKEYBYTES,
    "sk must be 'crypto_box_SECRETKEYBYTES' bytes"
  )

  return binding.crypto_box_open_easy(m, c, n, pk, sk)
}

exports.crypto_box_open_detached = function (m, c, mac, n, pk, sk) {
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(mac), 'mac must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(ArrayBuffer.isView(sk), 'sk must be a typed array')
  assert(m.byteLength === c.byteLength, "m must be 'c.byteLength' bytes")
  assert(mac.byteLength === exports.crypto_box_MACBYTES, "mac must be 'crypto_box_MACBYTES' bytes")
  assert(n.byteLength === exports.crypto_box_NONCEBYTES, "n must be 'crypto_box_NONCEBYTES' bytes")
  assert(
    pk.byteLength === exports.crypto_box_PUBLICKEYBYTES,
    "pk must be 'crypto_box_PUBLICKEYBYTES' bytes"
  )
  assert(
    sk.byteLength === exports.crypto_box_SECRETKEYBYTES,
    "sk must be 'crypto_box_SECRETKEYBYTES' bytes"
  )

  return binding.crypto_box_open_detached(m, c, mac, n, pk, sk)
}

exports.crypto_box_seal = function (c, m, pk) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(
    c.byteLength === m.byteLength + exports.crypto_box_SEALBYTES,
    "c must be 'm.byteLength + crypto_box_SEALBYTES' bytes"
  )
  assert(
    pk.byteLength === exports.crypto_box_PUBLICKEYBYTES,
    "pk must be 'crypto_box_PUBLICKEYBYTES' bytes"
  )

  const res = binding.crypto_box_seal(c, m, pk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_box_seal_open = function (m, c, pk, sk) {
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(ArrayBuffer.isView(sk), 'sk must be a typed array')
  assert(
    c.byteLength >= exports.crypto_box_SEALBYTES,
    "c must be at least 'crypto_box_SEALBYTES' bytes"
  )
  assert(
    m.byteLength === c.byteLength - exports.crypto_box_SEALBYTES,
    "m must be 'c.byteLength - crypto_box_SEALBYTES' bytes"
  )
  assert(
    pk.byteLength === exports.crypto_box_PUBLICKEYBYTES,
    "pk must be 'crypto_box_PUBLICKEYBYTES' bytes"
  )
  assert(
    sk.byteLength === exports.crypto_box_SECRETKEYBYTES,
    "sk must be 'crypto_box_SECRETKEYBYTES' bytes"
  )

  return binding.crypto_box_seal_open(
    m.buffer,
    m.byteOffset,
    m.byteLength,

    c.buffer,
    c.byteOffset,
    c.byteLength,

    pk.buffer,
    pk.byteOffset,
    pk.byteLength,

    sk.buffer,
    sk.byteOffset,
    sk.byteLength
  )
}

// crypto_secretbox

exports.crypto_secretbox_easy = function (c, m, n, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    c.byteLength === m.byteLength + binding.crypto_secretbox_MACBYTES,
    "c must be 'm.byteLength + crypto_secretbox_MACBYTES' bytes"
  )
  assert(
    n.byteLength === binding.crypto_secretbox_NONCEBYTES,
    "n must be 'crypto_secretbox_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_secretbox_KEYBYTES,
    "k must be 'crypto_secretbox_KEYBYTES' bytes"
  )

  const res = binding.crypto_secretbox_easy(c, m, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_secretbox_open_easy = function (m, c, n, k) {
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    c.byteLength >= binding.crypto_secretbox_MACBYTES,
    "c must be at least 'crypto_secretbox_MACBYTES' bytes"
  )
  assert(
    m.byteLength === c.byteLength - binding.crypto_secretbox_MACBYTES,
    "m must be 'c.byteLength - crypto_secretbox_MACBYTES' bytes"
  )
  assert(
    n.byteLength === binding.crypto_secretbox_NONCEBYTES,
    "n must be 'crypto_secretbox_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_secretbox_KEYBYTES,
    "k must be 'crypto_secretbox_KEYBYTES' bytes"
  )

  return binding.crypto_secretbox_open_easy(m, c, n, k)
}

exports.crypto_secretbox_detached = function (c, mac, m, n, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(mac), 'mac must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")
  assert(
    mac.byteLength === binding.crypto_secretbox_MACBYTES,
    "mac must be 'crypto_secretbox_MACBYTES' bytes"
  )
  assert(
    n.byteLength === binding.crypto_secretbox_NONCEBYTES,
    "n must be 'crypto_secretbox_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_secretbox_KEYBYTES,
    "k must be 'crypto_secretbox_KEYBYTES' bytes"
  )

  const res = binding.crypto_secretbox_detached(c, mac, m, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_secretbox_open_detached = function (m, c, mac, n, k) {
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(mac), 'mac must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(m.byteLength === c.byteLength, "m must be 'c.byteLength' bytes")
  assert(
    mac.byteLength === binding.crypto_secretbox_MACBYTES,
    "mac must be 'crypto_secretbox_MACBYTES' bytes"
  )
  assert(
    n.byteLength === binding.crypto_secretbox_NONCEBYTES,
    "n must be 'crypto_secretbox_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_secretbox_KEYBYTES,
    "k must be 'crypto_secretbox_KEYBYTES' bytes"
  )

  return binding.crypto_secretbox_open_detached(m, c, mac, n, k)
}

// crypto_generichash

exports.crypto_generichash = function (output, input, key) {
  if (!key) key = OPTIONAL

  assert(ArrayBuffer.isView(output), 'output must be a typed array')
  assert(ArrayBuffer.isView(input), 'input must be a typed array')
  assert(
    output.byteLength >= binding.crypto_generichash_BYTES_MIN &&
      output.byteLength <= binding.crypto_generichash_BYTES_MAX,
    'output must be between crypto_generichash_BYTES_MIN and crypto_generichash_BYTES_MAX bytes'
  )

  if (key !== OPTIONAL) {
    assert(ArrayBuffer.isView(key), 'key must be a typed array')
    assert(
      key.byteLength >= binding.crypto_generichash_KEYBYTES_MIN &&
        key.byteLength <= binding.crypto_generichash_KEYBYTES_MAX,
      'key must be between crypto_generichash_KEYBYTES_MIN and crypto_generichash_KEYBYTES_MAX bytes'
    )
  }

  const res = binding.crypto_generichash(
    output.buffer,
    output.byteOffset,
    output.byteLength,

    input.buffer,
    input.byteOffset,
    input.byteLength,

    key.buffer,
    key.byteOffset,
    key.byteLength
  )

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_generichash_batch = function (output, batch, key) {
  assert(ArrayBuffer.isView(output), 'output must be a typed array')

  if (isNode || batch.length < 4) {
    const res = binding.crypto_generichash_batch(output, batch, !!key, key || OPTIONAL)
    if (res !== 0) throw new Error('status: ' + res)
  } else {
    const state = Buffer.alloc(binding.crypto_generichash_STATEBYTES)

    exports.crypto_generichash_init(state, key, output.byteLength)

    for (const buf of batch) {
      exports.crypto_generichash_update(state, buf)
    }

    exports.crypto_generichash_final(state, output)
  }
}

exports.crypto_generichash_keygen = function (key) {
  assert(ArrayBuffer.isView(key), 'key must be a typed array')
  assert(
    key.byteLength === binding.crypto_generichash_KEYBYTES,
    "key must be 'crypto_generichash_KEYBYTES' bytes"
  )

  const res = binding.crypto_generichash_keygen(key.buffer, key.byteOffset, key.byteLength)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_generichash_init = function (state, key, outputLength) {
  if (!key) key = OPTIONAL

  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_generichash_STATEBYTES,
    "state must be 'crypto_generichash_STATEBYTES' bytes"
  )

  const res = binding.crypto_generichash_init(
    state.buffer,
    state.byteOffset,
    state.byteLength,

    key.buffer,
    key.byteOffset,
    key.byteLength,

    outputLength
  )

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_generichash_update = function (state, input) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(ArrayBuffer.isView(input), 'input must be a typed array')
  assert(
    state.byteLength === binding.crypto_generichash_STATEBYTES,
    "state must be 'crypto_generichash_STATEBYTES' bytes"
  )

  const res = binding.crypto_generichash_update(
    state.buffer,
    state.byteOffset,
    state.byteLength,

    input.buffer,
    input.byteOffset,
    input.byteLength
  )

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_generichash_final = function (state, output) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(ArrayBuffer.isView(output), 'output must be a typed array')
  assert(
    state.byteLength === binding.crypto_generichash_STATEBYTES,
    "state must be 'crypto_generichash_STATEBYTES' bytes"
  )

  const res = binding.crypto_generichash_final(
    state.buffer,
    state.byteOffset,
    state.byteLength,

    output.buffer,
    output.byteOffset,
    output.byteLength
  )

  if (res !== 0) throw new Error('status: ' + res)
}

// secretstream

exports.crypto_secretstream_xchacha20poly1305_keygen = function (k) {
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_secretstream_xchacha20poly1305_KEYBYTES,
    "k must be 'crypto_secretstream_xchacha20poly1305_KEYBYTES' bytes"
  )

  binding.crypto_secretstream_xchacha20poly1305_keygen(k.buffer, k.byteOffset, k.byteLength)
}

exports.crypto_secretstream_xchacha20poly1305_init_push = function (state, header, k) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(ArrayBuffer.isView(header), 'header must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    state.byteLength === binding.crypto_secretstream_xchacha20poly1305_STATEBYTES,
    "state must be 'crypto_secretstream_xchacha20poly1305_STATEBYTES' bytes"
  )
  assert(
    header.byteLength === binding.crypto_secretstream_xchacha20poly1305_HEADERBYTES,
    "header must be 'crypto_secretstream_xchacha20poly1305_HEADERBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_secretstream_xchacha20poly1305_KEYBYTES,
    "k must be 'crypto_secretstream_xchacha20poly1305_KEYBYTES' bytes"
  )

  const res = binding.crypto_secretstream_xchacha20poly1305_init_push(
    state.buffer,
    state.byteOffset,
    state.byteLength,

    header.buffer,
    header.byteOffset,
    header.byteLength,

    k.buffer,
    k.byteOffset,
    k.byteLength
  )

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_secretstream_xchacha20poly1305_init_pull = function (state, header, k) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(ArrayBuffer.isView(header), 'header must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    state.byteLength === binding.crypto_secretstream_xchacha20poly1305_STATEBYTES,
    "state must be 'crypto_secretstream_xchacha20poly1305_STATEBYTES' bytes"
  )
  assert(
    header.byteLength === binding.crypto_secretstream_xchacha20poly1305_HEADERBYTES,
    "header must be 'crypto_secretstream_xchacha20poly1305_HEADERBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_secretstream_xchacha20poly1305_KEYBYTES,
    "k must be 'crypto_secretstream_xchacha20poly1305_KEYBYTES' bytes"
  )

  const res = binding.crypto_secretstream_xchacha20poly1305_init_pull(
    state.buffer,
    state.byteOffset,
    state.byteLength,

    header.buffer,
    header.byteOffset,
    header.byteLength,

    k.buffer,
    k.byteOffset,
    k.byteLength
  )

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_secretstream_xchacha20poly1305_push = function (state, c, m, ad, tag) {
  if (!ad) ad = OPTIONAL

  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(
    state.byteLength === binding.crypto_secretstream_xchacha20poly1305_STATEBYTES,
    "state must be 'crypto_secretstream_xchacha20poly1305_STATEBYTES' bytes"
  )
  assert(
    c.byteLength === m.byteLength + binding.crypto_secretstream_xchacha20poly1305_ABYTES,
    "c must be 'm.byteLength + crypto_secretstream_xchacha20poly1305_ABYTES' bytes"
  )

  const res = binding.crypto_secretstream_xchacha20poly1305_push(
    state.buffer,
    state.byteOffset,
    state.byteLength,

    c.buffer,
    c.byteOffset,
    c.byteLength,

    m.buffer,
    m.byteOffset,
    m.byteLength,

    ad.buffer,
    ad.byteOffset,
    ad.byteLength,

    tag
  )

  if (res < 0) throw new Error('push failed')

  return res
}

exports.crypto_secretstream_xchacha20poly1305_pull = function (state, m, tag, c, ad) {
  if (!ad) ad = OPTIONAL

  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_secretstream_xchacha20poly1305_STATEBYTES,
    "state must be 'crypto_secretstream_xchacha20poly1305_STATEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(tag), 'tag must be a typed array')
  assert(tag.byteLength === 1, 'tag must be 1 byte')

  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(
    c.byteLength >= binding.crypto_secretstream_xchacha20poly1305_ABYTES,
    "c must be at least 'crypto_secretstream_xchacha20poly1305_ABYTES' bytes"
  )
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(
    m.byteLength === c.byteLength - binding.crypto_secretstream_xchacha20poly1305_ABYTES,
    "m must be 'c.byteLength - crypto_secretstream_xchacha20poly1305_ABYTES' bytes"
  )

  const res = binding.crypto_secretstream_xchacha20poly1305_pull(
    state.buffer,
    state.byteOffset,
    state.byteLength,

    m.buffer,
    m.byteOffset,
    m.byteLength,

    tag.buffer,
    tag.byteOffset,
    tag.byteLength,

    c.buffer,
    c.byteOffset,
    c.byteLength,

    ad.buffer,
    ad.byteOffset,
    ad.byteLength
  )

  if (res < 0) throw new Error('pull failed')

  return res
}

exports.crypto_secretstream_xchacha20poly1305_rekey = function (state) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_secretstream_xchacha20poly1305_STATEBYTES,
    "state must be 'crypto_secretstream_xchacha20poly1305_STATEBYTES' bytes"
  )

  binding.crypto_secretstream_xchacha20poly1305_rekey(
    state.buffer,
    state.byteOffset,
    state.byteLength
  )
}

// crypto_stream

exports.crypto_stream = function (c, n, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    n.byteLength === binding.crypto_stream_NONCEBYTES,
    "n must be 'crypto_stream_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_stream_KEYBYTES,
    "k must be 'crypto_stream_KEYBYTES' bytes"
  )

  const res = binding.crypto_stream(c, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_xor = function (c, m, n, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")
  assert(
    n.byteLength === binding.crypto_stream_NONCEBYTES,
    "n must be 'crypto_stream_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_stream_KEYBYTES,
    "k must be 'crypto_stream_KEYBYTES' bytes"
  )

  const res = binding.crypto_stream_xor(
    c.buffer,
    c.byteOffset,
    c.byteLength,

    m.buffer,
    m.byteOffset,
    m.byteLength,

    n.buffer,
    n.byteOffset,
    n.byteLength,

    k.buffer,
    k.byteOffset,
    k.byteLength
  )

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_chacha20 = function (c, n, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    n.byteLength === binding.crypto_stream_chacha20_NONCEBYTES,
    "n must be 'crypto_stream_chacha20_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_stream_chacha20_KEYBYTES,
    "k must be 'crypto_stream_chacha20_KEYBYTES' bytes"
  )

  const res = binding.crypto_stream_chacha20(c, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_chacha20_xor = function (c, m, n, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")
  assert(
    n.byteLength === binding.crypto_stream_chacha20_NONCEBYTES,
    "n must be 'crypto_stream_chacha20_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_stream_chacha20_KEYBYTES,
    "k must be 'crypto_stream_chacha20_KEYBYTES' bytes"
  )

  const res = binding.crypto_stream_chacha20_xor(c, m, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_chacha20_xor_ic = function (c, m, n, ic, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")
  assert(
    n.byteLength === binding.crypto_stream_chacha20_NONCEBYTES,
    "n must be 'crypto_stream_chacha20_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_stream_chacha20_KEYBYTES,
    "k must be 'crypto_stream_chacha20_KEYBYTES' bytes"
  )

  const res = binding.crypto_stream_chacha20_xor_ic(c, m, n, ic, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_chacha20_ietf = function (c, n, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    n.byteLength === binding.crypto_stream_chacha20_ietf_NONCEBYTES,
    "n must be 'crypto_stream_chacha20_ietf_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_stream_chacha20_ietf_KEYBYTES,
    "k must be 'crypto_stream_chacha20_ietf_KEYBYTES' bytes"
  )

  const res = binding.crypto_stream_chacha20_ietf(c, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_chacha20_ietf_xor = function (c, m, n, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")
  assert(
    n.byteLength === binding.crypto_stream_chacha20_ietf_NONCEBYTES,
    "n must be 'crypto_stream_chacha20_ietf_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_stream_chacha20_ietf_KEYBYTES,
    "k must be 'crypto_stream_chacha20_ietf_KEYBYTES' bytes"
  )

  const res = binding.crypto_stream_chacha20_ietf_xor(c, m, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_chacha20_ietf_xor_ic = function (c, m, n, ic, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")
  assert(
    n.byteLength === binding.crypto_stream_chacha20_ietf_NONCEBYTES,
    "n must be 'crypto_stream_chacha20_ietf_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_stream_chacha20_ietf_KEYBYTES,
    "k must be 'crypto_stream_chacha20_ietf_KEYBYTES' bytes"
  )

  const res = binding.crypto_stream_chacha20_ietf_xor_ic(c, m, n, ic, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_xchacha20 = function (c, n, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    n.byteLength === binding.crypto_stream_xchacha20_NONCEBYTES,
    "n must be 'crypto_stream_xchacha20_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_stream_xchacha20_KEYBYTES,
    "k must be 'crypto_stream_xchacha20_KEYBYTES' bytes"
  )

  const res = binding.crypto_stream_xchacha20(c, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_xchacha20_xor = function (c, m, n, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")
  assert(
    n.byteLength === binding.crypto_stream_xchacha20_NONCEBYTES,
    "n must be 'crypto_stream_xchacha20_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_stream_xchacha20_KEYBYTES,
    "k must be 'crypto_stream_xchacha20_KEYBYTES' bytes"
  )

  const res = binding.crypto_stream_xchacha20_xor(c, m, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_xchacha20_xor_ic = function (c, m, n, ic, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")
  assert(
    n.byteLength === binding.crypto_stream_xchacha20_NONCEBYTES,
    "n must be 'crypto_stream_xchacha20_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_stream_xchacha20_KEYBYTES,
    "k must be 'crypto_stream_xchacha20_KEYBYTES' bytes"
  )

  const res = binding.crypto_stream_xchacha20_xor_ic(c, m, n, ic, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_salsa20 = function (c, n, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    n.byteLength === binding.crypto_stream_salsa20_NONCEBYTES,
    "n must be 'crypto_stream_salsa20_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_stream_salsa20_KEYBYTES,
    "k must be 'crypto_stream_salsa20_KEYBYTES' bytes"
  )

  const res = binding.crypto_stream_salsa20(c, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_salsa20_xor = function (c, m, n, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")
  assert(
    n.byteLength === binding.crypto_stream_salsa20_NONCEBYTES,
    "n must be 'crypto_stream_salsa20_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_stream_salsa20_KEYBYTES,
    "k must be 'crypto_stream_salsa20_KEYBYTES' bytes"
  )

  const res = binding.crypto_stream_salsa20_xor(c, m, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_salsa20_xor_ic = function (c, m, n, ic, k) {
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")
  assert(
    n.byteLength === binding.crypto_stream_salsa20_NONCEBYTES,
    "n must be 'crypto_stream_salsa20_NONCEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_stream_salsa20_KEYBYTES,
    "k must be 'crypto_stream_salsa20_KEYBYTES' bytes"
  )

  const res = binding.crypto_stream_salsa20_xor_ic(c, m, n, ic, k)

  if (res !== 0) throw new Error('status: ' + res)
}

// crypto_auth

exports.crypto_auth = function (out, input, k) {
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(ArrayBuffer.isView(input), 'input must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(out.byteLength === binding.crypto_auth_BYTES, "out must be 'crypto_auth_BYTES' bytes")
  assert(k.byteLength === binding.crypto_auth_KEYBYTES, "k must be 'crypto_auth_KEYBYTES' bytes")

  const res = binding.crypto_auth(out, input, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_auth_verify = function (h, input, k) {
  assert(ArrayBuffer.isView(h), 'h must be a typed array')
  assert(ArrayBuffer.isView(input), 'input must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(h.byteLength === binding.crypto_auth_BYTES, "h must be 'crypto_auth_BYTES' bytes")
  assert(k.byteLength === binding.crypto_auth_KEYBYTES, "k must be 'crypto_auth_KEYBYTES' bytes")

  return binding.crypto_auth_verify(h, input, k)
}

// crypto_onetimeauth

exports.crypto_onetimeauth = function (out, input, k) {
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(ArrayBuffer.isView(input), 'input must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    out.byteLength === binding.crypto_onetimeauth_BYTES,
    "out must be 'crypto_onetimeauth_BYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_onetimeauth_KEYBYTES,
    "k must be 'crypto_onetimeauth_KEYBYTES' bytes"
  )

  const res = binding.crypto_onetimeauth(out, input, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_onetimeauth_init = function (state, k) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    state.byteLength === binding.crypto_onetimeauth_STATEBYTES,
    "state must be 'crypto_onetimeauth_STATEBYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_onetimeauth_KEYBYTES,
    "k must be 'crypto_onetimeauth_KEYBYTES' bytes"
  )

  const res = binding.crypto_onetimeauth_init(state, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_onetimeauth_update = function (state, input) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(ArrayBuffer.isView(input), 'input must be a typed array')
  assert(
    state.byteLength === binding.crypto_onetimeauth_STATEBYTES,
    "state must be 'crypto_onetimeauth_STATEBYTES' bytes"
  )

  const res = binding.crypto_onetimeauth_update(state, input)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_onetimeauth_final = function (state, out) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(
    state.byteLength === binding.crypto_onetimeauth_STATEBYTES,
    "state must be 'crypto_onetimeauth_STATEBYTES' bytes"
  )
  assert(
    out.byteLength === binding.crypto_onetimeauth_BYTES,
    "out must be 'crypto_onetimeauth_BYTES' bytes"
  )

  const res = binding.crypto_onetimeauth_final(state, out)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_onetimeauth_verify = function (h, input, k) {
  assert(ArrayBuffer.isView(h), 'h must be a typed array')
  assert(ArrayBuffer.isView(input), 'input must be a typed array')
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    h.byteLength === binding.crypto_onetimeauth_BYTES,
    "h must be 'crypto_onetimeauth_BYTES' bytes"
  )
  assert(
    k.byteLength === binding.crypto_onetimeauth_KEYBYTES,
    "k must be 'crypto_onetimeauth_KEYBYTES' bytes"
  )

  return binding.crypto_onetimeauth_verify(h, input, k)
}

// crypto_pwhash

exports.crypto_pwhash = function (out, passwd, salt, opslimit, memlimit, alg) {
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(ArrayBuffer.isView(passwd), 'passwd must be a typed array')
  assert(ArrayBuffer.isView(salt), 'salt must be a typed array')
  assert(
    out.byteLength >= binding.crypto_pwhash_BYTES_MIN,
    "out must be at least 'crypto_pwhash_BYTES_MIN' bytes"
  )
  assert(
    out.byteLength <= binding.crypto_pwhash_BYTES_MAX,
    "out must be at most 'crypto_pwhash_BYTES_MAX' bytes"
  )
  assert(
    salt.byteLength === binding.crypto_pwhash_SALTBYTES,
    "salt must be 'crypto_pwhash_SALTBYTES' bytes"
  )
  assert(
    opslimit >= binding.crypto_pwhash_OPSLIMIT_MIN,
    "opslimit must be at least 'crypto_pwhash_OPSLIMIT_MIN'"
  )
  assert(
    opslimit <= binding.crypto_pwhash_OPSLIMIT_MAX,
    "opslimit must be at most 'crypto_pwhash_OPSLIMIT_MAX'"
  )
  assert(
    memlimit >= binding.crypto_pwhash_MEMLIMIT_MIN,
    "memlimit must be at least 'crypto_pwhash_MEMLIMIT_MIN'"
  )
  assert(
    memlimit <= binding.crypto_pwhash_MEMLIMIT_MAX,
    "memlimit must be at most 'crypto_pwhash_MEMLIMIT_MAX'"
  )
  assert(alg >= 1 && alg <= 2, 'alg must be either Argon2i 1.3 or Argon2id 1.3')

  const res = binding.crypto_pwhash(out, passwd, salt, opslimit, memlimit, alg)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_pwhash_async = function (
  out,
  passwd,
  salt,
  opslimit,
  memlimit,
  alg,
  callback = undefined
) {
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(ArrayBuffer.isView(passwd), 'passwd must be a typed array')
  assert(ArrayBuffer.isView(salt), 'salt must be a typed array')
  assert(
    out.byteLength >= binding.crypto_pwhash_BYTES_MIN,
    "out must be at least 'crypto_pwhash_BYTES_MIN' bytes"
  )
  assert(
    out.byteLength <= binding.crypto_pwhash_BYTES_MAX,
    "out must be at most 'crypto_pwhash_BYTES_MAX' bytes"
  )
  assert(
    salt.byteLength === binding.crypto_pwhash_SALTBYTES,
    "salt must be 'crypto_pwhash_SALTBYTES' bytes"
  )
  assert(
    opslimit >= binding.crypto_pwhash_OPSLIMIT_MIN,
    "opslimit must be at least 'crypto_pwhash_OPSLIMIT_MIN'"
  )
  assert(
    opslimit <= binding.crypto_pwhash_OPSLIMIT_MAX,
    "opslimit must be at most 'crypto_pwhash_OPSLIMIT_MAX'"
  )
  assert(
    memlimit >= binding.crypto_pwhash_MEMLIMIT_MIN,
    "memlimit must be at least 'crypto_pwhash_MEMLIMIT_MIN'"
  )
  assert(
    memlimit <= binding.crypto_pwhash_MEMLIMIT_MAX,
    "memlimit must be at most 'crypto_pwhash_MEMLIMIT_MAX'"
  )
  assert(alg >= 1 && alg <= 2, 'alg must be either Argon2i 1.3 or Argon2id 1.3')

  const [done, promise] = checkStatus(callback)

  binding.crypto_pwhash_async(
    out.buffer,
    out.byteOffset,
    out.byteLength,

    passwd.buffer,
    passwd.byteOffset,
    passwd.byteLength,

    salt.buffer,
    salt.byteOffset,
    salt.byteLength,

    opslimit,
    memlimit,
    alg,

    done
  )

  return promise
}

exports.crypto_pwhash_str = function (out, passwd, opslimit, memlimit) {
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(ArrayBuffer.isView(passwd), 'passwd must be a typed array')
  assert(
    out.byteLength === binding.crypto_pwhash_STRBYTES,
    "out must be 'crypto_pwhash_STRBYTES' bytes"
  )
  assert(typeof opslimit === 'number', 'opslimit must be a number')
  assert(
    opslimit >= binding.crypto_pwhash_OPSLIMIT_MIN,
    "opslimit must be at least 'crypto_pwhash_OPSLIMIT_MIN'"
  )
  assert(
    opslimit <= binding.crypto_pwhash_OPSLIMIT_MAX,
    "opslimit must be at most 'crypto_pwhash_OPSLIMIT_MAX'"
  )
  assert(typeof memlimit === 'number', 'memlimit must be a number')
  assert(
    memlimit >= binding.crypto_pwhash_MEMLIMIT_MIN,
    "memlimit must be at least 'crypto_pwhash_MEMLIMIT_MIN'"
  )
  assert(
    memlimit <= binding.crypto_pwhash_MEMLIMIT_MAX,
    "memlimit must be at most 'crypto_pwhash_MEMLIMIT_MAX'"
  )

  const res = binding.crypto_pwhash_str(out, passwd, opslimit, memlimit)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_pwhash_str_async = function (out, passwd, opslimit, memlimit, callback = undefined) {
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(ArrayBuffer.isView(passwd), 'passwd must be a typed array')
  assert(
    out.byteLength === binding.crypto_pwhash_STRBYTES,
    "out must be 'crypto_pwhash_STRBYTES' bytes"
  )
  assert(passwd.byteLength > 0, 'passwd must not be empty')
  assert(typeof opslimit === 'number', 'opslimit must be a number')
  assert(
    opslimit >= binding.crypto_pwhash_OPSLIMIT_MIN,
    "opslimit must be at least 'crypto_pwhash_OPSLIMIT_MIN'"
  )
  assert(
    opslimit <= binding.crypto_pwhash_OPSLIMIT_MAX,
    "opslimit must be at most 'crypto_pwhash_OPSLIMIT_MAX'"
  )
  assert(typeof memlimit === 'number', 'memlimit must be a number')
  assert(
    memlimit >= binding.crypto_pwhash_MEMLIMIT_MIN,
    "memlimit must be at least 'crypto_pwhash_MEMLIMIT_MIN'"
  )
  assert(
    memlimit <= binding.crypto_pwhash_MEMLIMIT_MAX,
    "memlimit must be at most 'crypto_pwhash_MEMLIMIT_MAX'"
  )

  const [done, promise] = checkStatus(callback)

  binding.crypto_pwhash_str_async(
    out.buffer,
    out.byteOffset,
    out.byteLength,

    passwd.buffer,
    passwd.byteOffset,
    passwd.byteLength,

    opslimit,
    memlimit,

    done
  )

  return promise
}

exports.crypto_pwhash_str_verify = function (str, passwd) {
  assert(ArrayBuffer.isView(str), 'str must be a typed array')
  assert(ArrayBuffer.isView(passwd), 'passwd must be a typed array')
  assert(
    str.byteLength === binding.crypto_pwhash_STRBYTES,
    "str must be 'crypto_pwhash_STRBYTES' bytes"
  )

  return binding.crypto_pwhash_str_verify(str, passwd)
}

exports.crypto_pwhash_str_verify_async = function (str, passwd, callback = undefined) {
  assert(ArrayBuffer.isView(str), 'str must be a typed array')
  assert(ArrayBuffer.isView(passwd), 'passwd must be a typed array')
  assert(
    str.byteLength === binding.crypto_pwhash_STRBYTES,
    "str must be 'crypto_pwhash_STRBYTES' bytes"
  )
  assert(passwd.byteLength > 0, 'passwd must not be empty')

  const [done, promise] = checkStatus(callback, true)

  binding.crypto_pwhash_str_verify_async(
    str.buffer,
    str.byteOffset,
    str.byteLength,

    passwd.buffer,
    passwd.byteOffset,
    passwd.byteLength,

    done
  )

  return promise
}

exports.crypto_pwhash_str_needs_rehash = function (str, opslimit, memlimit) {
  assert(ArrayBuffer.isView(str), 'str must be a typed array')
  assert(
    str.byteLength === binding.crypto_pwhash_STRBYTES,
    "str must be 'crypto_pwhash_STRBYTES' bytes"
  )
  assert(
    opslimit >= binding.crypto_pwhash_OPSLIMIT_MIN,
    "opslimit must be at least 'crypto_pwhash_OPSLIMIT_MIN'"
  )
  assert(
    opslimit <= binding.crypto_pwhash_OPSLIMIT_MAX,
    "opslimit must be at most 'crypto_pwhash_OPSLIMIT_MAX'"
  )
  assert(
    memlimit >= binding.crypto_pwhash_MEMLIMIT_MIN,
    "memlimit must be at least 'crypto_pwhash_MEMLIMIT_MIN'"
  )
  assert(
    memlimit <= binding.crypto_pwhash_MEMLIMIT_MAX,
    "memlimit must be at most 'crypto_pwhash_MEMLIMIT_MAX'"
  )

  return binding.crypto_pwhash_str_needs_rehash(str, opslimit, memlimit)
}

exports.crypto_pwhash_scryptsalsa208sha256 = function (out, passwd, salt, opslimit, memlimit) {
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(ArrayBuffer.isView(passwd), 'passwd must be a typed array')
  assert(ArrayBuffer.isView(salt), 'salt must be a typed array')
  assert(
    out.byteLength >= binding.crypto_pwhash_scryptsalsa208sha256_BYTES_MIN,
    "out must be at least 'crypto_pwhash_scryptsalsa208sha256_BYTES_MIN' bytes"
  )
  assert(
    out.byteLength <= binding.crypto_pwhash_scryptsalsa208sha256_BYTES_MAX,
    "out must be at most 'crypto_pwhash_scryptsalsa208sha256_BYTES_MAX' bytes"
  )
  assert(
    salt.byteLength === binding.crypto_pwhash_scryptsalsa208sha256_SALTBYTES,
    "salt must be 'crypto_pwhash_scryptsalsa208sha256_SALTBYTES' bytes"
  )
  assert(
    opslimit >= binding.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN,
    "opslimit must be at least 'crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN'"
  )
  assert(
    opslimit <= binding.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX,
    "opslimit must be at most 'crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX'"
  )
  assert(
    memlimit >= binding.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN,
    "memlimit must be at least 'crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN'"
  )
  assert(
    memlimit <= binding.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX,
    "memlimit must be at most 'crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX'"
  )

  const res = binding.crypto_pwhash_scryptsalsa208sha256(out, passwd, salt, opslimit, memlimit)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_pwhash_scryptsalsa208sha256_async = function (
  out,
  passwd,
  salt,
  opslimit,
  memlimit,
  callback = undefined
) {
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(ArrayBuffer.isView(passwd), 'passwd must be a typed array')
  assert(ArrayBuffer.isView(salt), 'salt must be a typed array')
  assert(
    out.byteLength >= binding.crypto_pwhash_scryptsalsa208sha256_BYTES_MIN,
    "out must be at least 'crypto_pwhash_scryptsalsa208sha256_BYTES_MIN' bytes"
  )
  assert(
    out.byteLength <= binding.crypto_pwhash_scryptsalsa208sha256_BYTES_MAX,
    "out must be at most 'crypto_pwhash_scryptsalsa208sha256_BYTES_MAX' bytes"
  )
  assert(passwd.byteLength > 0, 'passwd must not be empty')
  assert(
    salt.byteLength === binding.crypto_pwhash_scryptsalsa208sha256_SALTBYTES,
    "salt must be 'crypto_pwhash_scryptsalsa208sha256_SALTBYTES' bytes"
  )
  assert(
    opslimit >= binding.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN,
    "opslimit must be at least 'crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN'"
  )
  assert(
    opslimit <= binding.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX,
    "opslimit must be at most 'crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX'"
  )
  assert(
    memlimit >= binding.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN,
    "memlimit must be at least 'crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN'"
  )
  assert(
    memlimit <= binding.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX,
    "memlimit must be at most 'crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX'"
  )

  const [done, promise] = checkStatus(callback)

  binding.crypto_pwhash_scryptsalsa208sha256_async(
    out.buffer,
    out.byteOffset,
    out.byteLength,

    passwd.buffer,
    passwd.byteOffset,
    passwd.byteLength,

    salt.buffer,
    salt.byteOffset,
    salt.byteLength,

    opslimit,
    memlimit,

    done
  )

  return promise
}

exports.crypto_pwhash_scryptsalsa208sha256_str_async = function (
  out,
  passwd,
  opslimit,
  memlimit,
  callback = undefined
) {
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(ArrayBuffer.isView(passwd), 'passwd must be a typed array')
  assert(
    out.byteLength === binding.crypto_pwhash_scryptsalsa208sha256_STRBYTES,
    "out must be 'crypto_pwhash_scryptsalsa208sha256_STRBYTES' bytes"
  )
  assert(passwd.byteLength > 0, 'passwd must not be empty')
  assert(
    opslimit >= binding.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN,
    "opslimit must be at least 'crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN'"
  )
  assert(
    opslimit <= binding.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX,
    "opslimit must be at most 'crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX'"
  )
  assert(
    memlimit >= binding.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN,
    "memlimit must be at least 'crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN'"
  )
  assert(
    memlimit <= binding.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX,
    "memlimit must be at most 'crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX'"
  )

  const [done, promise] = checkStatus(callback)

  binding.crypto_pwhash_scryptsalsa208sha256_str_async(
    out.buffer,
    out.byteOffset,
    out.byteLength,

    passwd.buffer,
    passwd.byteOffset,
    passwd.byteLength,

    opslimit,
    memlimit,

    done
  )

  return promise
}

exports.crypto_pwhash_scryptsalsa208sha256_str = function (out, passwd, opslimit, memlimit) {
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(ArrayBuffer.isView(passwd), 'passwd must be a typed array')
  assert(
    out.byteLength === binding.crypto_pwhash_scryptsalsa208sha256_STRBYTES,
    "out must be 'crypto_pwhash_scryptsalsa208sha256_STRBYTES' bytes"
  )
  assert(passwd.byteLength > 0, 'passwd must not be empty')
  assert(
    opslimit >= binding.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN,
    "opslimit must be at least 'crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN'"
  )
  assert(
    opslimit <= binding.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX,
    "opslimit must be at most 'crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX'"
  )
  assert(
    memlimit >= binding.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN,
    "memlimit must be at least 'crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN'"
  )
  assert(
    memlimit <= binding.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX,
    "memlimit must be at most 'crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX'"
  )

  const res = binding.crypto_pwhash_scryptsalsa208sha256_str(out, passwd, opslimit, memlimit)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_pwhash_scryptsalsa208sha256_str_verify_async = function (
  str,
  passwd,
  callback = undefined
) {
  assert(ArrayBuffer.isView(str), 'str must be a typed array')
  assert(ArrayBuffer.isView(passwd), 'passwd must be a typed array')
  assert(
    str.byteLength === binding.crypto_pwhash_scryptsalsa208sha256_STRBYTES,
    "str must be 'crypto_pwhash_scryptsalsa208sha256_STRBYTES' bytes"
  )
  assert(passwd.byteLength > 0, 'passwd must not be empty')

  const [done, promise] = checkStatus(callback, true)

  binding.crypto_pwhash_scryptsalsa208sha256_str_verify_async(
    str.buffer,
    str.byteOffset,
    str.byteLength,

    passwd.buffer,
    passwd.byteOffset,
    passwd.byteLength,

    done
  )

  return promise
}

exports.crypto_pwhash_scryptsalsa208sha256_str_verify = function (str, passwd) {
  assert(ArrayBuffer.isView(str), 'str must be a typed array')
  assert(ArrayBuffer.isView(passwd), 'passwd must be a typed array')
  assert(
    str.byteLength === binding.crypto_pwhash_scryptsalsa208sha256_STRBYTES,
    "str must be 'crypto_pwhash_scryptsalsa208sha256_STRBYTES' bytes"
  )
  assert(passwd.byteLength > 0, 'passwd must not be empty')

  return binding.crypto_pwhash_scryptsalsa208sha256_str_verify(str, passwd)
}

exports.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash = function (str, opslimit, memlimit) {
  assert(ArrayBuffer.isView(str), 'str must be a typed array')
  assert(
    str.byteLength === binding.crypto_pwhash_scryptsalsa208sha256_STRBYTES,
    "str must be 'crypto_pwhash_scryptsalsa208sha256_STRBYTES' bytes"
  )
  assert(
    opslimit >= binding.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN,
    "opslimit must be at least 'crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN'"
  )
  assert(
    opslimit <= binding.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX,
    "opslimit must be at most 'crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX'"
  )
  assert(
    memlimit >= binding.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN,
    "memlimit must be at least 'crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN'"
  )
  assert(
    memlimit <= binding.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX,
    "memlimit must be at most 'crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX'"
  )

  return binding.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(str, opslimit, memlimit)
}

// crypto_kx

exports.crypto_kx_keypair = function (pk, sk) {
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(ArrayBuffer.isView(sk), 'sk must be a typed array')
  assert(
    pk.byteLength === binding.crypto_kx_PUBLICKEYBYTES,
    "pk must be 'crypto_kx_PUBLICKEYBYTES' bytes"
  )
  assert(
    sk.byteLength === binding.crypto_kx_SECRETKEYBYTES,
    "sk must be 'crypto_kx_SECRETKEYBYTES' bytes"
  )

  const res = binding.crypto_kx_keypair(pk, sk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_kx_seed_keypair = function (pk, sk, seed) {
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(ArrayBuffer.isView(sk), 'sk must be a typed array')
  assert(ArrayBuffer.isView(seed), 'seed must be a typed array')
  assert(
    pk.byteLength === binding.crypto_kx_PUBLICKEYBYTES,
    "pk must be 'crypto_kx_PUBLICKEYBYTES' bytes"
  )
  assert(
    sk.byteLength === binding.crypto_kx_SECRETKEYBYTES,
    "sk must be 'crypto_kx_SECRETKEYBYTES' bytes"
  )
  assert(
    seed.byteLength === binding.crypto_kx_SEEDBYTES,
    "seed must be 'crypto_kx_SEEDBYTES' bytes"
  )

  const res = binding.crypto_kx_seed_keypair(pk, sk, seed)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_kx_client_session_keys = function (rx, tx, clientPk, clientSk, serverPk) {
  if (!rx) rx = undefined
  if (!tx) tx = undefined

  assert(rx || tx, 'at least one session key must be specified')

  if (rx) {
    assert(ArrayBuffer.isView(rx), 'rx must be a typed array')
    assert(
      rx.byteLength === binding.crypto_kx_SESSIONKEYBYTES,
      "rx must be 'crypto_kx_SESSIONKEYBYTES' bytes"
    )
  }

  if (tx) {
    assert(ArrayBuffer.isView(tx), 'tx must be a typed array')
    assert(
      tx.byteLength === binding.crypto_kx_SESSIONKEYBYTES,
      "tx must be 'crypto_kx_SESSIONKEYBYTES' bytes"
    )
  }

  assert(ArrayBuffer.isView(clientPk), 'clientPk must be a typed array')
  assert(ArrayBuffer.isView(clientSk), 'clientSk must be a typed array')
  assert(ArrayBuffer.isView(serverPk), 'serverPk must be a typed array')
  assert(
    clientPk.byteLength === binding.crypto_kx_PUBLICKEYBYTES,
    "clientPk must be 'crypto_kx_PUBLICKEYBYTES' bytes"
  )
  assert(
    clientSk.byteLength === binding.crypto_kx_SECRETKEYBYTES,
    "clientSk must be 'crypto_kx_SECRETKEYBYTES' bytes"
  )
  assert(
    serverPk.byteLength === binding.crypto_kx_PUBLICKEYBYTES,
    "serverPk must be 'crypto_kx_PUBLICKEYBYTES' bytes"
  )

  const res = binding.crypto_kx_client_session_keys(rx, tx, clientPk, clientSk, serverPk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_kx_server_session_keys = function (rx, tx, serverPk, serverSk, clientPk) {
  if (!rx) rx = undefined
  if (!tx) tx = undefined

  assert(rx || tx, 'at least one session key must be specified')

  if (rx) {
    assert(ArrayBuffer.isView(rx), 'rx must be a typed array')
    assert(
      rx.byteLength === binding.crypto_kx_SESSIONKEYBYTES,
      "rx must be 'crypto_kx_SESSIONKEYBYTES' bytes"
    )
  }

  if (tx) {
    assert(ArrayBuffer.isView(tx), 'tx must be a typed array')
    assert(
      tx.byteLength === binding.crypto_kx_SESSIONKEYBYTES,
      "tx must be 'crypto_kx_SESSIONKEYBYTES' bytes"
    )
  }

  assert(ArrayBuffer.isView(serverPk), 'serverPk must be a typed array')
  assert(ArrayBuffer.isView(serverSk), 'serverSk must be a typed array')
  assert(ArrayBuffer.isView(clientPk), 'clientPk must be a typed array')
  assert(
    serverPk.byteLength === binding.crypto_kx_PUBLICKEYBYTES,
    "serverPk must be 'crypto_kx_PUBLICKEYBYTES' bytes"
  )
  assert(
    serverSk.byteLength === binding.crypto_kx_SECRETKEYBYTES,
    "serverSk must be 'crypto_kx_SECRETKEYBYTES' bytes"
  )
  assert(
    clientPk.byteLength === binding.crypto_kx_PUBLICKEYBYTES,
    "clientPk must be 'crypto_kx_PUBLICKEYBYTES' bytes"
  )

  const res = binding.crypto_kx_server_session_keys(rx, tx, serverPk, serverSk, clientPk)

  if (res !== 0) throw new Error('status: ' + res)
}

// crypto_scalarmult

exports.crypto_scalarmult_base = function (q, n) {
  assert(ArrayBuffer.isView(q), 'q must be a typed array')
  assert(
    q.byteLength === binding.crypto_scalarmult_BYTES,
    "q must be 'crypto_scalarmult_BYTES' bytes"
  )
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(
    n.byteLength === binding.crypto_scalarmult_SCALARBYTES,
    "n must be 'crypto_scalarmult_SCALARBYTES' bytes"
  )

  const res = binding.crypto_scalarmult_base(q, n)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_scalarmult = function (q, n, p) {
  assert(ArrayBuffer.isView(q), 'q must be a typed array')
  assert(
    q.byteLength === binding.crypto_scalarmult_BYTES,
    "q must be 'crypto_scalarmult_BYTES' bytes"
  )
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(
    n.byteLength === binding.crypto_scalarmult_SCALARBYTES,
    "n must be 'crypto_scalarmult_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(p), 'p must be a typed array')
  assert(
    p.byteLength === binding.crypto_scalarmult_BYTES,
    "p must be 'crypto_scalarmult_BYTES' bytes"
  )

  const res = binding.crypto_scalarmult(q, n, p)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_scalarmult_ed25519_base = function (q, n) {
  assert(ArrayBuffer.isView(q), 'q must be a typed array')
  assert(
    q.byteLength === binding.crypto_scalarmult_ed25519_BYTES,
    "q must be 'crypto_scalarmult_ed25519_BYTES' bytes"
  )
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(
    n.byteLength === binding.crypto_scalarmult_ed25519_SCALARBYTES,
    "n must be 'crypto_scalarmult_ed25519_SCALARBYTES' bytes"
  )

  const res = binding.crypto_scalarmult_ed25519_base(q, n)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_scalarmult_ed25519 = function (q, n, p) {
  assert(ArrayBuffer.isView(q), 'q must be a typed array')
  assert(
    q.byteLength === binding.crypto_scalarmult_ed25519_BYTES,
    "q must be 'crypto_scalarmult_ed25519_BYTES' bytes"
  )
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(
    n.byteLength === binding.crypto_scalarmult_ed25519_SCALARBYTES,
    "n must be 'crypto_scalarmult_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(p), 'p must be a typed array')
  assert(
    p.byteLength === binding.crypto_scalarmult_ed25519_BYTES,
    "p must be 'crypto_scalarmult_ed25519_BYTES' bytes"
  )

  const res = binding.crypto_scalarmult_ed25519(q, n, p)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_core_ed25519_is_valid_point = function (p) {
  assert(ArrayBuffer.isView(p), 'p must be a typed array')
  assert(
    p.byteLength === binding.crypto_core_ed25519_BYTES,
    "p must be 'crypto_core_ed25519_BYTES' bytes"
  )

  return binding.crypto_core_ed25519_is_valid_point(p)
}

exports.crypto_core_ed25519_from_uniform = function (p, r) {
  assert(ArrayBuffer.isView(p), 'p must be a typed array')
  assert(
    p.byteLength === binding.crypto_core_ed25519_BYTES,
    "p must be 'crypto_core_ed25519_BYTES' bytes"
  )
  assert(ArrayBuffer.isView(r), 'r must be a typed array')
  assert(
    r.byteLength === binding.crypto_core_ed25519_UNIFORMBYTES,
    "r must be 'crypto_core_ed25519_UNIFORMBYTES' bytes"
  )

  const res = binding.crypto_core_ed25519_from_uniform(p, r)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_scalarmult_ed25519_base_noclamp = function (q, n) {
  assert(ArrayBuffer.isView(q), 'q must be a typed array')
  assert(
    q.byteLength === binding.crypto_scalarmult_ed25519_BYTES,
    "q must be 'crypto_scalarmult_ed25519_BYTES' bytes"
  )
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(
    n.byteLength === binding.crypto_scalarmult_ed25519_SCALARBYTES,
    "n must be 'crypto_scalarmult_ed25519_SCALARBYTES' bytes"
  )

  const res = binding.crypto_scalarmult_ed25519_base_noclamp(q, n)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_scalarmult_ed25519_noclamp = function (q, n, p) {
  assert(ArrayBuffer.isView(q), 'q must be a typed array')
  assert(
    q.byteLength === binding.crypto_scalarmult_ed25519_BYTES,
    "q must be 'crypto_scalarmult_ed25519_BYTES' bytes"
  )
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(
    n.byteLength === binding.crypto_scalarmult_ed25519_SCALARBYTES,
    "n must be 'crypto_scalarmult_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(p), 'p must be a typed array')
  assert(
    p.byteLength === binding.crypto_scalarmult_ed25519_BYTES,
    "p must be 'crypto_scalarmult_ed25519_BYTES' bytes"
  )

  const res = binding.crypto_scalarmult_ed25519_noclamp(q, n, p)

  if (res !== 0) throw new Error('status: ' + res)
}

// crypto_core

exports.crypto_core_ed25519_add = function (r, p, q) {
  assert(ArrayBuffer.isView(r), 'r must be a typed array')
  assert(
    r.byteLength === binding.crypto_core_ed25519_BYTES,
    "r must be 'crypto_core_ed25519_BYTES' bytes"
  )
  assert(ArrayBuffer.isView(p), 'p must be a typed array')
  assert(
    p.byteLength === binding.crypto_core_ed25519_BYTES,
    "p must be 'crypto_core_ed25519_BYTES' bytes"
  )
  assert(ArrayBuffer.isView(q), 'q must be a typed array')
  assert(
    q.byteLength === binding.crypto_core_ed25519_BYTES,
    "q must be 'crypto_core_ed25519_BYTES' bytes"
  )

  const res = binding.crypto_core_ed25519_add(r, p, q)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_core_ed25519_sub = function (r, p, q) {
  assert(ArrayBuffer.isView(r), 'r must be a typed array')
  assert(
    r.byteLength === binding.crypto_core_ed25519_BYTES,
    "r must be 'crypto_core_ed25519_BYTES' bytes"
  )
  assert(ArrayBuffer.isView(p), 'p must be a typed array')
  assert(
    p.byteLength === binding.crypto_core_ed25519_BYTES,
    "p must be 'crypto_core_ed25519_BYTES' bytes"
  )
  assert(ArrayBuffer.isView(q), 'q must be a typed array')
  assert(
    q.byteLength === binding.crypto_core_ed25519_BYTES,
    "q must be 'crypto_core_ed25519_BYTES' bytes"
  )

  const res = binding.crypto_core_ed25519_sub(r, p, q)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_core_ed25519_scalar_random = function (r) {
  assert(ArrayBuffer.isView(r), 'r must be a typed array')
  assert(
    r.byteLength === binding.crypto_core_ed25519_SCALARBYTES,
    "r must be 'crypto_core_ed25519_SCALARBYTES' bytes"
  )

  binding.crypto_core_ed25519_scalar_random(r)
}

exports.crypto_core_ed25519_scalar_reduce = function (r, s) {
  assert(ArrayBuffer.isView(r), 'r must be a typed array')
  assert(
    r.byteLength === binding.crypto_core_ed25519_SCALARBYTES,
    "r must be 'crypto_core_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(s), 's must be a typed array')
  assert(
    s.byteLength === binding.crypto_core_ed25519_NONREDUCEDSCALARBYTES,
    "s must be 'crypto_core_ed25519_NONREDUCEDSCALARBYTES' bytes"
  )

  binding.crypto_core_ed25519_scalar_reduce(r, s)
}

exports.crypto_core_ed25519_scalar_invert = function (recip, s) {
  assert(ArrayBuffer.isView(recip), 'recip must be a typed array')
  assert(
    recip.byteLength === binding.crypto_core_ed25519_SCALARBYTES,
    "recip must be 'crypto_core_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(s), 's must be a typed array')
  assert(
    s.byteLength === binding.crypto_core_ed25519_SCALARBYTES,
    "s must be 'crypto_core_ed25519_SCALARBYTES' bytes"
  )

  binding.crypto_core_ed25519_scalar_invert(recip, s)
}

exports.crypto_core_ed25519_scalar_negate = function (neg, s) {
  assert(ArrayBuffer.isView(neg), 'neg must be a typed array')
  assert(
    neg.byteLength === binding.crypto_core_ed25519_SCALARBYTES,
    "neg must be 'crypto_core_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(s), 's must be a typed array')
  assert(
    s.byteLength === binding.crypto_core_ed25519_SCALARBYTES,
    "s must be 'crypto_core_ed25519_SCALARBYTES' bytes"
  )

  binding.crypto_core_ed25519_scalar_negate(neg, s)
}

exports.crypto_core_ed25519_scalar_complement = function (comp, s) {
  assert(ArrayBuffer.isView(comp), 'comp must be a typed array')
  assert(
    comp.byteLength === binding.crypto_core_ed25519_SCALARBYTES,
    "comp must be 'crypto_core_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(s), 's must be a typed array')
  assert(
    s.byteLength === binding.crypto_core_ed25519_SCALARBYTES,
    "s must be 'crypto_core_ed25519_SCALARBYTES' bytes"
  )

  binding.crypto_core_ed25519_scalar_complement(comp, s)
}

exports.crypto_core_ed25519_scalar_add = function (z, x, y) {
  assert(ArrayBuffer.isView(z), 'z must be a typed array')
  assert(
    z.byteLength === binding.crypto_core_ed25519_SCALARBYTES,
    "z must be 'crypto_core_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(x), 'x must be a typed array')
  assert(
    x.byteLength === binding.crypto_core_ed25519_SCALARBYTES,
    "x must be 'crypto_core_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(y), 'y must be a typed array')
  assert(
    y.byteLength === binding.crypto_core_ed25519_SCALARBYTES,
    "y must be 'crypto_core_ed25519_SCALARBYTES' bytes"
  )

  binding.crypto_core_ed25519_scalar_add(z, x, y)
}

exports.crypto_core_ed25519_scalar_sub = function (z, x, y) {
  assert(ArrayBuffer.isView(z), 'z must be a typed array')
  assert(
    z.byteLength === binding.crypto_core_ed25519_SCALARBYTES,
    "z must be 'crypto_core_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(x), 'x must be a typed array')
  assert(
    x.byteLength === binding.crypto_core_ed25519_SCALARBYTES,
    "x must be 'crypto_core_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(y), 'y must be a typed array')
  assert(
    y.byteLength === binding.crypto_core_ed25519_SCALARBYTES,
    "y must be 'crypto_core_ed25519_SCALARBYTES' bytes"
  )

  binding.crypto_core_ed25519_scalar_sub(z, x, y)
}

// crypto_shorthash

exports.crypto_shorthash = function (out, input, k) {
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(ArrayBuffer.isView(input), 'input must be a typed array')
  assert(
    out.byteLength === binding.crypto_shorthash_BYTES,
    "out must be 'crypto_shorthash_BYTES' bytes"
  )
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_shorthash_KEYBYTES,
    "k must be 'crypto_shorthash_KEYBYTES' bytes"
  )

  const res = binding.crypto_shorthash(out, input, k)

  if (res !== 0) throw new Error('status: ' + res)
}

// crypto_kdf

exports.crypto_kdf_keygen = function (key) {
  assert(ArrayBuffer.isView(key), 'key must be a typed array')
  assert(key.byteLength === binding.crypto_kdf_KEYBYTES, "key must be 'crypto_kdf_KEYBYTES' bytes")

  binding.crypto_kdf_keygen(key)
}

exports.crypto_kdf_derive_from_key = function (subkey, subkeyId, ctx, key) {
  assert(ArrayBuffer.isView(subkey), 'subkey must be a typed array')
  assert(
    subkey.byteLength >= binding.crypto_kdf_BYTES_MIN,
    "subkey must be at least 'crypto_kdf_BYTES_MIN' bytes"
  )
  assert(
    subkey.byteLength <= binding.crypto_kdf_BYTES_MAX,
    "subkey must be at most 'crypto_kdf_BYTES_MAX' bytes"
  )
  assert(ArrayBuffer.isView(ctx), 'ctx must be a typed array')
  assert(
    ctx.byteLength === binding.crypto_kdf_CONTEXTBYTES,
    "ctx must be 'crypto_kdf_CONTEXTBYTES' bytes"
  )
  assert(ArrayBuffer.isView(key), 'key must be a typed array')
  assert(key.byteLength === binding.crypto_kdf_KEYBYTES, "key must be 'crypto_kdf_KEYBYTES' bytes")

  const res = binding.crypto_kdf_derive_from_key(subkey, subkeyId, ctx, key)

  if (res !== 0) throw new Error('status: ' + res)
}

// crypto_hash

exports.crypto_hash = function (out, input) {
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(ArrayBuffer.isView(input), 'input must be a typed array')
  assert(out.byteLength === binding.crypto_hash_BYTES, "out must be 'crypto_hash_BYTES' bytes")

  const res = binding.crypto_hash(out, input)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_hash_sha256 = function (out, input) {
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(ArrayBuffer.isView(input), 'input must be a typed array')
  assert(
    out.byteLength === binding.crypto_hash_sha256_BYTES,
    "out must be 'crypto_hash_sha256_BYTES' bytes"
  )

  const res = binding.crypto_hash_sha256(out, input)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_hash_sha256_init = function (state) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_hash_sha256_STATEBYTES,
    "state must be 'crypto_hash_sha256_STATEBYTES' bytes"
  )

  const res = binding.crypto_hash_sha256_init(state)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_hash_sha256_update = function (state, input) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(ArrayBuffer.isView(input), 'input must be a typed array')
  assert(
    state.byteLength === binding.crypto_hash_sha256_STATEBYTES,
    "state must be 'crypto_hash_sha256_STATEBYTES' bytes"
  )

  const res = binding.crypto_hash_sha256_update(state, input)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_hash_sha256_final = function (state, out) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_hash_sha256_STATEBYTES,
    "state must be 'crypto_hash_sha256_STATEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(
    out.byteLength === binding.crypto_hash_sha256_BYTES,
    "out must be 'crypto_hash_sha256_BYTES' bytes"
  )

  const res = binding.crypto_hash_sha256_final(state, out)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_hash_sha512 = function (out, input) {
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(ArrayBuffer.isView(input), 'input must be a typed array')
  assert(
    out.byteLength === binding.crypto_hash_sha512_BYTES,
    "out must be 'crypto_hash_sha512_BYTES' bytes"
  )

  const res = binding.crypto_hash_sha512(out, input)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_hash_sha512_init = function (state) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_hash_sha512_STATEBYTES,
    "state must be 'crypto_hash_sha512_STATEBYTES' bytes"
  )

  const res = binding.crypto_hash_sha512_init(state)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_hash_sha512_update = function (state, input) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(ArrayBuffer.isView(input), 'input must be a typed array')
  assert(
    state.byteLength === binding.crypto_hash_sha512_STATEBYTES,
    "state must be 'crypto_hash_sha512_STATEBYTES' bytes"
  )

  const res = binding.crypto_hash_sha512_update(state, input)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_hash_sha512_final = function (state, out) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_hash_sha512_STATEBYTES,
    "state must be 'crypto_hash_sha512_STATEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(
    out.byteLength === binding.crypto_hash_sha512_BYTES,
    "out must be 'crypto_hash_sha512_BYTES' bytes"
  )

  const res = binding.crypto_hash_sha512_final(state, out)

  if (res !== 0) throw new Error('status: ' + res)
}

// crypto_aead

exports.crypto_aead_xchacha20poly1305_ietf_keygen = function (k) {
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    "k must be 'crypto_aead_xchacha20poly1305_ietf_KEYBYTES' bytes"
  )

  binding.crypto_aead_xchacha20poly1305_ietf_keygen(k)
}

exports.crypto_aead_xchacha20poly1305_ietf_encrypt = function (c, m, ad, nsec, npub, k) {
  if (!ad) ad = undefined

  assert(nsec === null, 'nsec must always be set to null')
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(
    c.byteLength === m.byteLength + binding.crypto_aead_xchacha20poly1305_ietf_ABYTES,
    "c must be 'm.byteLength + crypto_aead_xchacha20poly1305_ietf_ABYTES' bytes"
  )
  assert(c.byteLength <= 0xffffffff, 'c.byteLength must be a 32bit integer')
  assert(ArrayBuffer.isView(npub), 'npub must be a typed array')
  assert(
    npub.byteLength === binding.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    "npub must be 'crypto_aead_xchacha20poly1305_ietf_NPUBBYTES' bytes"
  )
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    "k must be 'crypto_aead_xchacha20poly1305_ietf_KEYBYTES' bytes"
  )

  const res = binding.crypto_aead_xchacha20poly1305_ietf_encrypt(c, m, ad, npub, k)

  if (res < 0) throw new Error('could not encrypt data')

  return res
}

exports.crypto_aead_xchacha20poly1305_ietf_decrypt = function (m, nsec, c, ad, npub, k) {
  if (!ad) ad = undefined

  assert(nsec === null, 'nsec must always be set to null')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(
    m.byteLength === c.byteLength - binding.crypto_aead_xchacha20poly1305_ietf_ABYTES,
    "m must be 'c.byteLength - crypto_aead_xchacha20poly1305_ietf_ABYTES' bytes"
  )
  assert(m.byteLength <= 0xffffffff, 'm.byteLength must be a 32bit integer')
  assert(ArrayBuffer.isView(npub), 'npub must be a typed array')
  assert(
    npub.byteLength === binding.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    "npub must be 'crypto_aead_xchacha20poly1305_ietf_NPUBBYTES' bytes"
  )
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    "k must be 'crypto_aead_xchacha20poly1305_ietf_KEYBYTES' bytes"
  )

  const res = binding.crypto_aead_xchacha20poly1305_ietf_decrypt(m, c, ad, npub, k)

  if (res < 0) throw new Error('could not verify data')

  return res
}

exports.crypto_aead_xchacha20poly1305_ietf_encrypt_detached = function (
  c,
  mac,
  m,
  ad,
  nsec,
  npub,
  k
) {
  if (!ad) ad = undefined

  assert(nsec === null, 'nsec must always be set to null')
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")
  assert(ArrayBuffer.isView(mac), 'mac must be a typed array')
  assert(
    mac.byteLength === binding.crypto_aead_xchacha20poly1305_ietf_ABYTES,
    "mac must be 'crypto_aead_xchacha20poly1305_ietf_ABYTES' bytes"
  )
  assert(ArrayBuffer.isView(npub), 'npub must be a typed array')
  assert(
    npub.byteLength === binding.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    "npub must be 'crypto_aead_xchacha20poly1305_ietf_NPUBBYTES' bytes"
  )
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    "k must be 'crypto_aead_xchacha20poly1305_ietf_KEYBYTES' bytes"
  )

  const res = binding.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, m, ad, npub, k)

  if (res < 0) throw new Error('could not encrypt data')

  return res
}

exports.crypto_aead_xchacha20poly1305_ietf_decrypt_detached = function (
  m,
  nsec,
  c,
  mac,
  ad,
  npub,
  k
) {
  if (!ad) ad = undefined

  assert(nsec === null, 'nsec must always be set to null')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(m.byteLength === c.byteLength, "m must be 'c.byteLength' bytes")
  assert(ArrayBuffer.isView(mac), 'mac must be a typed array')
  assert(
    mac.byteLength === binding.crypto_aead_xchacha20poly1305_ietf_ABYTES,
    "mac must be 'crypto_aead_xchacha20poly1305_ietf_ABYTES' bytes"
  )
  assert(ArrayBuffer.isView(npub), 'npub must be a typed array')
  assert(
    npub.byteLength === binding.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    "npub must be 'crypto_aead_xchacha20poly1305_ietf_NPUBBYTES' bytes"
  )
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    "k must be 'crypto_aead_xchacha20poly1305_ietf_KEYBYTES' bytes"
  )

  const res = binding.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m, c, mac, ad, npub, k)

  if (res !== 0) throw new Error('could not verify data')
}

exports.crypto_aead_chacha20poly1305_ietf_keygen = function (k) {
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    "k must be 'crypto_aead_chacha20poly1305_ietf_KEYBYTES' bytes"
  )

  binding.crypto_aead_chacha20poly1305_ietf_keygen(k)
}

exports.crypto_aead_chacha20poly1305_ietf_encrypt = function (c, m, ad, nsec, npub, k) {
  if (!ad) ad = undefined

  assert(nsec === null, 'nsec must always be set to null')
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(
    c.byteLength === m.byteLength + binding.crypto_aead_chacha20poly1305_ietf_ABYTES,
    "c must be 'm.byteLength + crypto_aead_chacha20poly1305_ietf_ABYTES' bytes"
  )
  assert(c.byteLength <= 0xffffffff, 'c.byteLength must be a 32bit integer')
  assert(ArrayBuffer.isView(npub), 'npub must be a typed array')
  assert(
    npub.byteLength === binding.crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
    "npub must be 'crypto_aead_chacha20poly1305_ietf_NPUBBYTES' bytes"
  )
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    "k must be 'crypto_aead_chacha20poly1305_ietf_KEYBYTES' bytes"
  )

  const res = binding.crypto_aead_chacha20poly1305_ietf_encrypt(c, m, ad, npub, k)

  if (res < 0) throw new Error('could not encrypt data')

  return res
}

exports.crypto_aead_chacha20poly1305_ietf_decrypt = function (m, nsec, c, ad, npub, k) {
  if (!ad) ad = undefined

  assert(nsec === null, 'nsec must always be set to null')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(
    m.byteLength === c.byteLength - binding.crypto_aead_chacha20poly1305_ietf_ABYTES,
    "m must be 'c.byteLength - crypto_aead_chacha20poly1305_ietf_ABYTES' bytes"
  )
  assert(m.byteLength <= 0xffffffff, 'm.byteLength must be a 32bit integer')
  assert(ArrayBuffer.isView(npub), 'npub must be a typed array')
  assert(
    npub.byteLength === binding.crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
    "npub must be 'crypto_aead_chacha20poly1305_ietf_NPUBBYTES' bytes"
  )
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    "k must be 'crypto_aead_chacha20poly1305_ietf_KEYBYTES' bytes"
  )

  const res = binding.crypto_aead_chacha20poly1305_ietf_decrypt(m, c, ad, npub, k)

  if (res < 0) throw new Error('could not verify data')

  return res
}

exports.crypto_aead_chacha20poly1305_ietf_encrypt_detached = function (
  c,
  mac,
  m,
  ad,
  nsec,
  npub,
  k
) {
  if (!ad) ad = undefined

  assert(nsec === null, 'nsec must always be set to null')
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")
  assert(ArrayBuffer.isView(mac), 'mac must be a typed array')
  assert(
    mac.byteLength === binding.crypto_aead_chacha20poly1305_ietf_ABYTES,
    "mac must be 'crypto_aead_chacha20poly1305_ietf_ABYTES' bytes"
  )
  assert(ArrayBuffer.isView(npub), 'npub must be a typed array')
  assert(
    npub.byteLength === binding.crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
    "npub must be 'crypto_aead_chacha20poly1305_ietf_NPUBBYTES' bytes"
  )
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    "k must be 'crypto_aead_chacha20poly1305_ietf_KEYBYTES' bytes"
  )

  const res = binding.crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, m, ad, npub, k)

  if (res < 0) throw new Error('could not encrypt data')

  return res
}

exports.crypto_aead_chacha20poly1305_ietf_decrypt_detached = function (
  m,
  nsec,
  c,
  mac,
  ad,
  npub,
  k
) {
  if (!ad) ad = undefined

  assert(nsec === null, 'nsec must always be set to null')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(m.byteLength === c.byteLength, "m must be 'c.byteLength' bytes")
  assert(ArrayBuffer.isView(mac), 'mac must be a typed array')
  assert(
    mac.byteLength === binding.crypto_aead_chacha20poly1305_ietf_ABYTES,
    "mac must be 'crypto_aead_chacha20poly1305_ietf_ABYTES' bytes"
  )
  assert(ArrayBuffer.isView(npub), 'npub must be a typed array')
  assert(
    npub.byteLength === binding.crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
    "npub must be 'crypto_aead_chacha20poly1305_ietf_NPUBBYTES' bytes"
  )
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    "k must be 'crypto_aead_chacha20poly1305_ietf_KEYBYTES' bytes"
  )

  const res = binding.crypto_aead_chacha20poly1305_ietf_decrypt_detached(m, c, mac, ad, npub, k)

  if (res !== 0) throw new Error('could not verify data')
}

// crypto_stream

exports.crypto_stream_xor_wrap_init = function (state, n, k) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.sn_crypto_stream_xor_STATEBYTES,
    "state must be 'sn_crypto_stream_xor_STATEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(
    n.byteLength === binding.crypto_stream_NONCEBYTES,
    "n must be 'crypto_stream_NONCEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_stream_KEYBYTES,
    "k must be 'crypto_stream_KEYBYTES' bytes"
  )

  binding.crypto_stream_xor_wrap_init(state, n, k)
}

exports.crypto_stream_xor_wrap_update = function (state, c, m) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.sn_crypto_stream_xor_STATEBYTES,
    "state must be 'sn_crypto_stream_xor_STATEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")

  binding.crypto_stream_xor_wrap_update(state, c, m)
}

exports.crypto_stream_xor_wrap_final = function (state) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.sn_crypto_stream_xor_STATEBYTES,
    "state must be 'sn_crypto_stream_xor_STATEBYTES' bytes"
  )

  binding.crypto_stream_xor_wrap_final(state)
}

exports.crypto_stream_chacha20_xor_wrap_init = function (state, n, k) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_stream_chacha20_xor_STATEBYTES,
    "state must be 'crypto_stream_chacha20_xor_STATEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(
    n.byteLength === binding.crypto_stream_chacha20_NONCEBYTES,
    "n must be 'crypto_stream_chacha20_NONCEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_stream_chacha20_KEYBYTES,
    "k must be 'crypto_stream_chacha20_KEYBYTES' bytes"
  )

  binding.crypto_stream_chacha20_xor_wrap_init(state, n, k)
}

exports.crypto_stream_chacha20_xor_wrap_update = function (state, c, m) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_stream_chacha20_xor_STATEBYTES,
    "state must be 'crypto_stream_chacha20_xor_STATEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")

  binding.crypto_stream_chacha20_xor_wrap_update(state, c, m)
}

exports.crypto_stream_chacha20_xor_wrap_final = function (state) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_stream_chacha20_xor_STATEBYTES,
    "state must be 'crypto_stream_chacha20_xor_STATEBYTES' bytes"
  )

  binding.crypto_stream_chacha20_xor_wrap_final(state)
}

exports.crypto_stream_chacha20_ietf_xor_wrap_init = function (state, n, k) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_stream_chacha20_ietf_xor_STATEBYTES,
    "state must be 'crypto_stream_chacha20_ietf_xor_STATEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(
    n.byteLength === binding.crypto_stream_chacha20_ietf_NONCEBYTES,
    "n must be 'crypto_stream_chacha20_ietf_NONCEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_stream_chacha20_ietf_KEYBYTES,
    "k must be 'crypto_stream_chacha20_ietf_KEYBYTES' bytes"
  )

  binding.crypto_stream_chacha20_ietf_xor_wrap_init(state, n, k)
}

exports.crypto_stream_chacha20_ietf_xor_wrap_update = function (state, c, m) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_stream_chacha20_ietf_xor_STATEBYTES,
    "state must be 'crypto_stream_chacha20_ietf_xor_STATEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")

  binding.crypto_stream_chacha20_ietf_xor_wrap_update(state, c, m)
}

exports.crypto_stream_chacha20_ietf_xor_wrap_final = function (state) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_stream_chacha20_ietf_xor_STATEBYTES,
    "state must be 'crypto_stream_chacha20_ietf_xor_STATEBYTES' bytes"
  )

  binding.crypto_stream_chacha20_ietf_xor_wrap_final(state)
}

exports.crypto_stream_xchacha20_xor_wrap_init = function (state, n, k) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_stream_xchacha20_xor_STATEBYTES,
    "state must be 'crypto_stream_xchacha20_xor_STATEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(
    n.byteLength === binding.crypto_stream_xchacha20_NONCEBYTES,
    "n must be 'crypto_stream_xchacha20_NONCEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_stream_xchacha20_KEYBYTES,
    "k must be 'crypto_stream_xchacha20_KEYBYTES' bytes"
  )

  binding.crypto_stream_xchacha20_xor_wrap_init(state, n, k)
}

exports.crypto_stream_xchacha20_xor_wrap_update = function (state, c, m) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_stream_xchacha20_xor_STATEBYTES,
    "state must be 'crypto_stream_xchacha20_xor_STATEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")

  binding.crypto_stream_xchacha20_xor_wrap_update(state, c, m)
}

exports.crypto_stream_xchacha20_xor_wrap_final = function (state) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_stream_xchacha20_xor_STATEBYTES,
    "state must be 'crypto_stream_xchacha20_xor_STATEBYTES' bytes"
  )

  binding.crypto_stream_xchacha20_xor_wrap_final(state)
}

exports.crypto_stream_salsa20_xor_wrap_init = function (state, n, k) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_stream_salsa20_xor_STATEBYTES,
    "state must be 'crypto_stream_salsa20_xor_STATEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(
    n.byteLength === binding.crypto_stream_salsa20_NONCEBYTES,
    "n must be 'crypto_stream_salsa20_NONCEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(k), 'k must be a typed array')
  assert(
    k.byteLength === binding.crypto_stream_salsa20_KEYBYTES,
    "k must be 'crypto_stream_salsa20_KEYBYTES' bytes"
  )

  binding.crypto_stream_salsa20_xor_wrap_init(state, n, k)
}

exports.crypto_stream_salsa20_xor_wrap_update = function (state, c, m) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_stream_salsa20_xor_STATEBYTES,
    "state must be 'crypto_stream_salsa20_xor_STATEBYTES' bytes"
  )
  assert(ArrayBuffer.isView(c), 'c must be a typed array')
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(c.byteLength === m.byteLength, "c must be 'm.byteLength' bytes")

  binding.crypto_stream_salsa20_xor_wrap_update(state, c, m)
}

exports.crypto_stream_salsa20_xor_wrap_final = function (state) {
  assert(ArrayBuffer.isView(state), 'state must be a typed array')
  assert(
    state.byteLength === binding.crypto_stream_salsa20_xor_STATEBYTES,
    "state must be 'crypto_stream_salsa20_xor_STATEBYTES' bytes"
  )

  binding.crypto_stream_salsa20_xor_wrap_final(state)
}

// experimental

exports.extension_tweak_ed25519_base = function (n, p, ns) {
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(
    n.byteLength === binding.extension_tweak_ed25519_SCALARBYTES,
    "n must be 'extension_tweak_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(p), 'p must be a typed array')
  assert(
    p.byteLength === binding.extension_tweak_ed25519_BYTES,
    "p must be 'extension_tweak_ed25519_BYTES' bytes"
  )

  binding.extension_tweak_ed25519_base(n, p, ns)
}

exports.extension_tweak_ed25519_sign_detached = function (sig, m, scalar, pk) {
  assert(ArrayBuffer.isView(sig), 'sig must be a typed array')
  assert(sig.byteLength === binding.crypto_sign_BYTES, "sig must be 'crypto_sign_BYTES' bytes")
  assert(ArrayBuffer.isView(m), 'm must be a typed array')
  assert(ArrayBuffer.isView(scalar), 'scalar must be a typed array')
  assert(
    scalar.byteLength === binding.extension_tweak_ed25519_SCALARBYTES,
    "scalar must be 'extension_tweak_ed25519_SCALARBYTES' bytes"
  )

  if (pk) {
    assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
    assert(
      pk.byteLength === binding.crypto_sign_PUBLICKEYBYTES,
      "pk must be 'crypto_sign_PUBLICKEYBYTES' bytes"
    )
  }

  const res = binding.extension_tweak_ed25519_sign_detached(sig, m, scalar, pk)

  if (res !== 0) throw new Error('failed to compute signature')
}

exports.extension_tweak_ed25519_sk_to_scalar = function (n, sk) {
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(
    n.byteLength === binding.extension_tweak_ed25519_SCALARBYTES,
    "n must be 'extension_tweak_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(sk), 'sk must be a typed array')
  assert(
    sk.byteLength === binding.crypto_sign_SECRETKEYBYTES,
    "sk must be 'crypto_sign_SECRETKEYBYTES' bytes"
  )

  binding.extension_tweak_ed25519_sk_to_scalar(n, sk)
}

exports.extension_tweak_ed25519_scalar = function (scalarOut, scalar, ns) {
  assert(ArrayBuffer.isView(scalarOut), 'scalarOut must be a typed array')
  assert(
    scalarOut.byteLength === binding.extension_tweak_ed25519_SCALARBYTES,
    "scalarOut must be 'extension_tweak_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(scalar), 'scalar must be a typed array')
  assert(
    scalar.byteLength === binding.extension_tweak_ed25519_SCALARBYTES,
    "scalar must be 'extension_tweak_ed25519_SCALARBYTES' bytes"
  )

  binding.extension_tweak_ed25519_scalar(scalarOut, scalar, ns)
}

exports.extension_tweak_ed25519_pk = function (tpk, pk, ns) {
  assert(ArrayBuffer.isView(tpk), 'tpk must be a typed array')
  assert(
    tpk.byteLength === binding.crypto_sign_PUBLICKEYBYTES,
    "tpk must be 'crypto_sign_PUBLICKEYBYTES' bytes"
  )
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(
    pk.byteLength === binding.crypto_sign_PUBLICKEYBYTES,
    "pk must be 'crypto_sign_PUBLICKEYBYTES' bytes"
  )

  const res = binding.extension_tweak_ed25519_pk(tpk, pk, ns)

  if (res !== 0) throw new Error('failed to tweak public key')
}

exports.extension_tweak_ed25519_keypair = function (pk, scalarOut, scalarIn, ns) {
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(
    pk.byteLength === binding.extension_tweak_ed25519_BYTES,
    "pk must be 'extension_tweak_ed25519_BYTES' bytes"
  )
  assert(ArrayBuffer.isView(scalarOut), 'scalarOut must be a typed array')
  assert(
    scalarOut.byteLength === binding.extension_tweak_ed25519_SCALARBYTES,
    "scalarOut must be 'extension_tweak_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(scalarIn), 'scalarIn must be a typed array')
  assert(
    scalarIn.byteLength === binding.extension_tweak_ed25519_SCALARBYTES,
    "scalarIn must be 'extension_tweak_ed25519_SCALARBYTES' bytes"
  )

  binding.extension_tweak_ed25519_keypair(pk, scalarOut, scalarIn, ns)
}

exports.extension_tweak_ed25519_scalar_add = function (scalarOut, scalar, n) {
  assert(ArrayBuffer.isView(scalarOut), 'scalarOut must be a typed array')
  assert(
    scalarOut.byteLength === binding.extension_tweak_ed25519_SCALARBYTES,
    "scalarOut must be 'extension_tweak_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(scalar), 'scalar must be a typed array')
  assert(
    scalar.byteLength === binding.extension_tweak_ed25519_SCALARBYTES,
    "scalar must be 'extension_tweak_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(n), 'n must be a typed array')
  assert(
    n.byteLength === binding.extension_tweak_ed25519_SCALARBYTES,
    "n must be 'extension_tweak_ed25519_SCALARBYTES' bytes"
  )

  binding.extension_tweak_ed25519_scalar_add(scalarOut, scalar, n)
}

exports.extension_tweak_ed25519_pk_add = function (tpk, pk, p) {
  assert(ArrayBuffer.isView(tpk), 'tpk must be a typed array')
  assert(
    tpk.byteLength === binding.crypto_sign_PUBLICKEYBYTES,
    "tpk must be 'crypto_sign_PUBLICKEYBYTES' bytes"
  )
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(
    pk.byteLength === binding.crypto_sign_PUBLICKEYBYTES,
    "pk must be 'crypto_sign_PUBLICKEYBYTES' bytes"
  )
  assert(ArrayBuffer.isView(p), 'p must be a typed array')
  assert(
    p.byteLength === binding.crypto_sign_PUBLICKEYBYTES,
    "p must be 'crypto_sign_PUBLICKEYBYTES' bytes"
  )

  const res = binding.extension_tweak_ed25519_pk_add(tpk, pk, p)

  if (res !== 0) throw new Error('failed to add tweak to public key')
}

exports.extension_tweak_ed25519_keypair_add = function (pk, scalarOut, scalarIn, tweak) {
  assert(ArrayBuffer.isView(pk), 'pk must be a typed array')
  assert(
    pk.byteLength === binding.extension_tweak_ed25519_BYTES,
    "pk must be 'extension_tweak_ed25519_BYTES' bytes"
  )
  assert(ArrayBuffer.isView(scalarOut), 'scalarOut must be a typed array')
  assert(
    scalarOut.byteLength === binding.extension_tweak_ed25519_SCALARBYTES,
    "scalarOut must be 'extension_tweak_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(scalarIn), 'scalarIn must be a typed array')
  assert(
    scalarIn.byteLength === binding.extension_tweak_ed25519_SCALARBYTES,
    "scalarIn must be 'extension_tweak_ed25519_SCALARBYTES' bytes"
  )
  assert(ArrayBuffer.isView(tweak), 'tweak must be a typed array')
  assert(
    tweak.byteLength === binding.extension_tweak_ed25519_SCALARBYTES,
    "tweak must be 'extension_tweak_ed25519_SCALARBYTES' bytes"
  )

  const res = binding.extension_tweak_ed25519_keypair_add(pk, scalarOut, scalarIn, tweak)

  if (res !== 0) throw new Error('failed to add tweak to keypair')
}

exports.extension_pbkdf2_sha512_async = function (out, passwd, salt, iter, outlen, callback) {
  assert(
    iter >= binding.extension_pbkdf2_sha512_ITERATIONS_MIN,
    "iter must be at least 'extension_pbkdf2_sha512_ITERATIONS_MIN'"
  )
  assert(
    outlen <= binding.extension_pbkdf2_sha512_BYTES_MAX,
    "outlen must be at most 'extension_pbkdf2_sha512_BYTES_MAX'"
  )
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(out.byteLength >= outlen, "out must be at least 'outlen' bytes")
  assert(out.byteLength > 0, 'out must not be empty')
  assert(ArrayBuffer.isView(passwd), 'passwd must be a typed array')
  assert(passwd.byteLength > 0, 'passwd must not be empty')
  assert(ArrayBuffer.isView(salt), 'salt must be a typed array')
  assert(salt.byteLength > 0, 'salt must not be empty')

  const [done, promise] = checkStatus(callback)

  binding.extension_pbkdf2_sha512_async(
    out.buffer,
    out.byteOffset,
    out.byteLength,

    passwd.buffer,
    passwd.byteOffset,
    passwd.byteLength,

    salt.buffer,
    salt.byteOffset,
    salt.byteLength,

    iter,
    outlen,

    done
  )

  return promise
}

exports.extension_pbkdf2_sha512 = function (out, passwd, salt, iter, outlen) {
  assert(
    iter >= binding.extension_pbkdf2_sha512_ITERATIONS_MIN,
    "iter must be at least 'extension_pbkdf2_sha512_ITERATIONS_MIN'"
  )
  assert(
    outlen <= binding.extension_pbkdf2_sha512_BYTES_MAX,
    "outlen must be at most 'extension_pbkdf2_sha512_BYTES_MAX'"
  )
  assert(ArrayBuffer.isView(out), 'out must be a typed array')
  assert(out.byteLength >= outlen, "out must be at least 'outlen' bytes")
  assert(out.byteLength > 0, 'out must not be empty')
  assert(ArrayBuffer.isView(passwd), 'passwd must be a typed array')
  assert(passwd.byteLength > 0, 'passwd must not be empty')
  assert(ArrayBuffer.isView(salt), 'salt must be a typed array')
  assert(salt.byteLength > 0, 'salt must not be empty')

  const res = binding.extension_pbkdf2_sha512(out, passwd, salt, iter, outlen)

  if (res !== 0) throw new Error('failed to add tweak to public key')
}

function checkStatus(callback, booleanResult = false) {
  let done, promise

  if (typeof callback === 'function') {
    done = function (status) {
      if (booleanResult) callback(null, status === 0)
      else if (status === 0) callback(null)
      else callback(new Error('status: ' + status))
    }
  } else {
    promise = new Promise(function (resolve, reject) {
      done = function (status) {
        if (booleanResult) resolve(status === 0)
        else if (status === 0) resolve()
        else reject(new Error('status: ' + status))
      }
    })
  }

  return [done, promise]
}
