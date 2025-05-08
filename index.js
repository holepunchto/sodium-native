const binding = require('./binding')
const { isNode } = require('which-runtime')
const OPTIONAL = Buffer.from(new ArrayBuffer(0))

module.exports = exports = { ...binding }

// memory

exports.sodium_malloc = function (size) {
  const buf = Buffer.from(binding.sodium_malloc(size))
  buf.secure = true

  return buf
}

// crypto_randombytes

exports.randombytes_buf = function (buffer) {
  binding.randombytes_buf(
    buffer.buffer, buffer.byteOffset, buffer.byteLength
  )
}

exports.randombytes_buf_deterministic = function (buffer, seed) {
  binding.randombytes_buf_deterministic(
    buffer.buffer, buffer.byteOffset, buffer.byteLength,
    seed.buffer, seed.byteOffset, seed.byteLength
  )
}

// sodium_helpers

exports.sodium_memcmp = function (a, b) {
  if (a.byteLength !== b.byteLength) throw new Error('buffers must be of same length"')
  return binding.sodium_memcmp(a, b)
}

exports.sodium_add = function (a, b) {
  if (a.byteLength !== b.byteLength) throw new Error('buffers must be of same length"')
  binding.sodium_add(a, b)
}

exports.sodium_sub = function (a, b) {
  if (a.byteLength !== b.byteLength) throw new Error('buffers must be of same length"')
  binding.sodium_sub(a, b)
}

/** @returns {number} */
exports.sodium_compare = function (a, b) {
  if (a.byteLength !== b.byteLength) throw new Error('buffers must be of same length"')
  return binding.sodium_compare(a, b)
}

/** @returns {boolean} */
exports.sodium_is_zero = function (buffer, length) {
  length ??= buffer.byteLength
  if (length > buffer.byteLength || length < 0) throw new Error('invalid length')

  return binding.sodium_is_zero(buffer, length)
}

/** @returns {number} padded buffer length */
exports.sodium_pad = function (buffer, unpaddedBuflen, blockSize) {
  if (unpaddedBuflen > buffer.byteLength) throw new Error('unpadded length cannot exceed buffer length')
  if (blockSize > buffer.byteLength) throw new Error('block size cannot exceed buffer length')
  if (blockSize < 1) throw new Error('block sizemust be at least 1 byte')
  if (buffer.byteLength < unpaddedBuflen + (blockSize - (unpaddedBuflen % blockSize))) throw new Error('buf not long enough')

  return binding.sodium_pad(buffer, unpaddedBuflen, blockSize)
}

/** @returns {number} unpadded buffer length */
exports.sodium_unpad = function (buffer, paddedBuflen, blockSize) {
  if (paddedBuflen > buffer.byteLength) throw new Error('unpadded length cannot exceed buffer length')
  if (blockSize > buffer.byteLength) throw new Error('block size cannot exceed buffer length')
  if (blockSize < 1) throw new Error('block size must be at least 1 byte')

  return binding.sodium_unpad(buffer, paddedBuflen, blockSize)
}

// crypto_sign

exports.crypto_sign_keypair = function (pk, sk) {
  if (pk.byteLength !== binding.crypto_sign_PUBLICKEYBYTES) throw new Error('pk')

  const res = binding.crypto_sign_keypair(pk, sk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_sign_seed_keypair = function (pk, sk, seed) {
  if (pk.byteLength !== binding.crypto_sign_PUBLICKEYBYTES) throw new Error('pk')

  const res = binding.crypto_sign_seed_keypair(pk, sk, seed)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_sign = function (sm, m, sk) {
  if (sm.byteLength !== binding.crypto_sign_BYTES + m.byteLength) throw new Error('sm must be "m.byteLength + crypto_sign_BYTES" bytes')
  if (sk.byteLength !== binding.crypto_sign_SECRETKEYBYTES) throw new Error('sk')

  const res = binding.crypto_sign(sm, m, sk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_sign_open = function (m, sm, pk) {
  if (m.byteLength !== sm.byteLength - binding.crypto_sign_BYTES) throw new Error('m must be "sm.byteLength - crypto_sign_BYTES" bytes')
  if (sm.byteLength < binding.crypto_sign_BYTES) throw new Error('sm')
  if (pk.byteLength !== binding.crypto_sign_PUBLICKEYBYTES) throw new Error('pk')

  const res = binding.crypto_sign_open(m, sm, pk)

  if (res !== 0) throw new Error('status: ' + res)
}

/** @returns {boolean} */
exports.crypto_sign_open = function (m, sm, pk) {
  if (m.byteLength !== sm.byteLength - binding.crypto_sign_BYTES) throw new Error('m must be "sm.byteLength - crypto_sign_BYTES" bytes')
  if (sm.byteLength < binding.crypto_sign_BYTES) throw new Error('sm')
  if (pk.byteLength !== binding.crypto_sign_PUBLICKEYBYTES) throw new Error('pk')

  return binding.crypto_sign_open(m, sm, pk)
}

exports.crypto_sign_detached = function (sig, m, sk) {
  if (sig.byteLength !== binding.crypto_sign_BYTES) throw new Error('sig')
  if (sk.byteLength !== binding.crypto_sign_SECRETKEYBYTES) throw new Error('sk')

  const res = binding.crypto_sign_detached(sig, m, sk)

  if (res !== 0) throw new Error('status: ' + res)
}

/** @returns {boolean} */
exports.crypto_sign_verify_detached = function (sig, m, pk) {
  return binding.crypto_sign_verify_detached(
    sig.buffer, sig.byteOffset, sig.byteLength,
    m.buffer, m.byteOffset, m.byteLength,
    pk.buffer, pk.byteOffset, pk.byteLength
  )
}

exports.crypto_sign_ed25519_sk_to_pk = function (pk, sk) {
  if (pk.byteLength !== binding.crypto_sign_PUBLICKEYBYTES) throw new Error('pk')
  if (sk.byteLength !== binding.crypto_sign_SECRETKEYBYTES) throw new Error('sk')

  const res = binding.crypto_sign_ed25519_sk_to_pk(pk, sk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_sign_ed25519_pk_to_curve25519 = function (x25519pk, ed25519pk) {
  if (x25519pk.byteLength !== binding.crypto_box_PUBLICKEYBYTES) throw new Error('x25519_pk')
  if (ed25519pk.byteLength !== binding.crypto_sign_PUBLICKEYBYTES) throw new Error('ed25519_pk')

  const res = binding.crypto_sign_ed25519_pk_to_curve25519(x25519pk, ed25519pk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_sign_ed25519_sk_to_curve25519 = function (x25519sk, ed25519sk) {
  if (x25519sk.byteLength !== binding.crypto_box_SECRETKEYBYTES) throw new Error('x25519_sk')

  const edLen = ed25519sk.byteLength

  if (edLen !== binding.crypto_sign_SECRETKEYBYTES && edLen !== binding.crypto_box_SECRETKEYBYTES) {
    throw new Error('ed25519_sk should either be \'crypto_sign_SECRETKEYBYTES\' bytes or \'crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES\' bytes')
  }

  const res = binding.crypto_sign_ed25519_sk_to_curve25519(x25519sk, ed25519sk)

  if (res !== 0) throw new Error('status: ' + res)
}

// crypto_box

exports.crypto_box_keypair = function (pk, sk) {
  if (pk.byteLength !== binding.crypto_box_PUBLICKEYBYTES) throw new Error('pk') // deprecated
  const res = binding.crypto_box_keypair(pk, sk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_box_seed_keypair = function (pk, sk, seed) {
  if (pk.byteLength !== binding.crypto_box_PUBLICKEYBYTES) throw new Error('pk') // deprecated
  const res = binding.crypto_box_seed_keypair(pk, sk, seed)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_box_easy = function (c, m, n, pk, sk) {
  const res = binding.crypto_box_easy(c, m, n, pk, sk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_box_detached = function (c, mac, m, n, pk, sk) {
  const res = binding.crypto_box_detached(c, mac, m, n, pk, sk)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_box_seal = function (c, m, pk) {
  const res = binding.crypto_box_seal(c, m, pk)

  if (res !== 0) throw new Error('status: ' + res)
}

/** @returns {boolean} */
exports.crypto_box_seal_open = function (m, c, pk, sk) {
  return binding.crypto_box_seal_open(
    m.buffer, m.byteOffset, m.byteLength,
    c.buffer, c.byteOffset, c.byteLength,
    pk.buffer, pk.byteOffset, pk.byteLength,
    sk.buffer, sk.byteOffset, sk.byteLength
  )
}

// crypto_secretbox

exports.crypto_secretbox_easy = function (c, m, n, k) {
  if (c.byteLength !== m.byteLength + binding.crypto_secretbox_MACBYTES) throw new Error('c must be "m.byteLength + crypto_secretbox_MACBYTES" bytes')
  if (n.byteLength !== binding.crypto_secretbox_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_secretbox_KEYBYTES) throw new Error('k')

  const res = binding.crypto_secretbox_easy(c, m, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

/** @returns {boolean} */
exports.crypto_secretbox_open_easy = function (m, c, n, k) {
  if (m.byteLength !== c.byteLength - binding.crypto_secretbox_MACBYTES) throw new Error('m must be "c - crypto_secretbox_MACBYTES" bytes')
  if (c.byteLength < binding.crypto_secretbox_MACBYTES) throw new Error('c')
  if (n.byteLength !== binding.crypto_secretbox_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_secretbox_KEYBYTES) throw new Error('k')

  return binding.crypto_secretbox_open_easy(m, c, n, k)
}

exports.crypto_secretbox_detached = function (c, mac, m, n, k) {
  if (c.byteLength !== m.byteLength) throw new Error('c must "m.byteLength" bytes')
  if (mac.byteLength !== binding.crypto_secretbox_MACBYTES) throw new Error('mac')
  if (n.byteLength !== binding.crypto_secretbox_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_secretbox_KEYBYTES) throw new Error('k')

  const res = binding.crypto_secretbox_detached(c, mac, m, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

/** @returns {boolean} */
exports.crypto_secretbox_open_detached = function (m, c, mac, n, k) {
  if (m.byteLength !== c.byteLength) throw new Error('m must be "c.byteLength" bytes')
  if (mac.byteLength !== binding.crypto_secretbox_MACBYTES) throw new Error('mac')
  if (n.byteLength !== binding.crypto_secretbox_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_secretbox_KEYBYTES) throw new Error('k')

  return binding.crypto_secretbox_open_detached(m, c, mac, n, k)
}

// crypto_generichash

exports.crypto_generichash = function (output, input, key = OPTIONAL) {
  const res = binding.crypto_generichash(
    output.buffer, output.byteOffset, output.byteLength,
    input.buffer, input.byteOffset, input.byteLength,
    key.buffer, key.byteOffset, key.byteLength
  )

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_generichash_batch = function (output, batch, key) {
  if (isNode || batch.length < 12) { // TODO: re-tune min-batch-size
    // iterate batch from native
    const res = binding.crypto_generichash_batch(output, batch, !!key, key || OPTIONAL)
    if (res !== 0) throw new Error('status: ' + res)
  } else {
    // iterate batch through fastcalls
    const state = Buffer.alloc(binding.crypto_generichash_STATEBYTES)

    exports.crypto_generichash_init(state, key, output.byteLength)

    for (const buf of batch) {
      exports.crypto_generichash_update(state, buf)
    }

    exports.crypto_generichash_final(state, output)
  }
}

exports.crypto_generichash_keygen = function (key) {
  const res = binding.crypto_generichash_keygen(
    key.buffer, key.byteOffset, key.byteLength
  )
  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_generichash_init = function (state, key, outputLength) {
  key ||= OPTIONAL

  const res = binding.crypto_generichash_init(
    state.buffer, state.byteOffset, state.byteLength,
    key.buffer, key.byteOffset, key.byteLength,
    outputLength
  )

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_generichash_update = function (state, input) {
  const res = binding.crypto_generichash_update(
    state.buffer, state.byteOffset, state.byteLength,
    input.buffer, input.byteOffset, input.byteLength
  )

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_generichash_final = function (state, output) {
  const res = binding.crypto_generichash_final(
    state.buffer, state.byteOffset, state.byteLength,
    output.buffer, output.byteOffset, output.byteLength
  )

  if (res !== 0) throw new Error('status: ' + res)
}

// secretstream

exports.crypto_secretstream_xchacha20poly1305_keygen = function (k) {
  binding.crypto_secretstream_xchacha20poly1305_keygen(k.buffer, k.byteOffset, k.byteLength)
}

exports.crypto_secretstream_xchacha20poly1305_init_push = function (state, header, k) {
  const res = binding.crypto_secretstream_xchacha20poly1305_init_push(
    state.buffer, state.byteOffset, state.byteLength,
    header.buffer, header.byteOffset, header.byteLength,
    k.buffer, k.byteOffset, k.byteLength
  )

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_secretstream_xchacha20poly1305_init_pull = function (state, header, k) {
  const res = binding.crypto_secretstream_xchacha20poly1305_init_pull(
    state.buffer, state.byteOffset, state.byteLength,
    header.buffer, header.byteOffset, header.byteLength,
    k.buffer, k.byteOffset, k.byteLength
  )

  if (res !== 0) throw new Error('status: ' + res)
}

/** @returns {number} */
exports.crypto_secretstream_xchacha20poly1305_push = function (state, c, m, ad, tag) {
  ad ||= OPTIONAL

  const res = binding.crypto_secretstream_xchacha20poly1305_push(
    state.buffer, state.byteOffset, state.byteLength,
    c.buffer, c.byteOffset, c.byteLength,
    m.buffer, m.byteOffset, m.byteLength,
    ad.buffer, ad.byteOffset, ad.byteLength,
    tag
  )

  if (res < 0) throw new Error('push failed')

  return res
}

/** @returns {number} */
exports.crypto_secretstream_xchacha20poly1305_pull = function (state, m, tag, c, ad) {
  ad ||= OPTIONAL

  // TODO: consider removing tests instead of throwing
  if (c.byteLength < binding.crypto_secretstream_xchacha20poly1305_ABYTES) throw new Error('invalid cipher length')
  if (m.byteLength !== c.byteLength - binding.crypto_secretstream_xchacha20poly1305_ABYTES) throw new Error('invalid message length')

  const res = binding.crypto_secretstream_xchacha20poly1305_pull(
    state.buffer, state.byteOffset, state.byteLength,
    m.buffer, m.byteOffset, m.byteLength,
    tag.buffer, tag.byteOffset, tag.byteLength,
    c.buffer, c.byteOffset, c.byteLength,
    ad.buffer, ad.byteOffset, ad.byteLength
  )

  if (res < 0) throw new Error('pull failed')

  return res
}

exports.crypto_secretstream_xchacha20poly1305_rekey = function (state) {
  binding.crypto_secretstream_xchacha20poly1305_rekey(state.buffer, state.byteOffset, state.byteLength)
}

// crypto_stream

exports.crypto_stream = function (c, n, k) {
  if (n.byteLength !== binding.crypto_stream_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_stream_KEYBYTES) throw new Error('k')

  const res = binding.crypto_stream(c, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_xor = function (c, m, n, k) {
  const res = binding.crypto_stream_xor(
    c.buffer, c.byteOffset, c.byteLength,
    m.buffer, m.byteOffset, m.byteLength,
    n.buffer, n.byteOffset, n.byteLength,
    k.buffer, k.byteOffset, k.byteLength
  )

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_chacha20 = function (c, n, k) {
  if (n.byteLength !== binding.crypto_stream_chacha20_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_stream_chacha20_KEYBYTES) throw new Error('k')

  const res = binding.crypto_stream_chacha20(c, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_chacha20_xor = function (c, m, n, k) {
  if (c.byteLength !== m.byteLength) throw new Error('m must be "c.byteLength" bytes')
  if (n.byteLength !== binding.crypto_stream_chacha20_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_stream_chacha20_KEYBYTES) throw new Error('k')

  const res = binding.crypto_stream_chacha20_xor(c, m, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_chacha20_xor_ic = function (c, m, n, ic, k) {
  if (c.byteLength !== m.byteLength) throw new Error('m must be "c.byteLength" bytes')
  if (n.byteLength !== binding.crypto_stream_chacha20_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_stream_chacha20_KEYBYTES) throw new Error('k')

  const res = binding.crypto_stream_chacha20_xor_ic(c, m, n, ic, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_chacha20_ietf = function (c, n, k) {
  if (n.byteLength !== binding.crypto_stream_chacha20_ietf_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_stream_chacha20_ietf_KEYBYTES) throw new Error('k')

  const res = binding.crypto_stream_chacha20_ietf(c, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_chacha20_ietf_xor = function (c, m, n, k) {
  if (c.byteLength !== m.byteLength) throw new Error('m must be "c.byteLength" bytes')
  if (n.byteLength !== binding.crypto_stream_chacha20_ietf_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_stream_chacha20_ietf_KEYBYTES) throw new Error('k')

  const res = binding.crypto_stream_chacha20_ietf_xor(c, m, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_chacha20_ietf_xor_ic = function (c, m, n, ic, k) {
  if (c.byteLength !== m.byteLength) throw new Error('m must be "c.byteLength" bytes')
  if (n.byteLength !== binding.crypto_stream_chacha20_ietf_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_stream_chacha20_ietf_KEYBYTES) throw new Error('k')

  const res = binding.crypto_stream_chacha20_ietf_xor_ic(c, m, n, ic, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_xchacha20 = function (c, n, k) {
  if (n.byteLength !== binding.crypto_stream_xchacha20_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_stream_xchacha20_KEYBYTES) throw new Error('k')

  const res = binding.crypto_stream_xchacha20(c, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_xchacha20_xor = function (c, m, n, k) {
  if (c.byteLength !== m.byteLength) throw new Error('m must be "c.byteLength" bytes')
  if (n.byteLength !== binding.crypto_stream_xchacha20_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_stream_xchacha20_KEYBYTES) throw new Error('k')

  const res = binding.crypto_stream_xchacha20_xor(c, m, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_xchacha20_xor_ic = function (c, m, n, ic, k) {
  if (c.byteLength !== m.byteLength) throw new Error('m must be "c.byteLength" bytes')
  if (n.byteLength !== binding.crypto_stream_xchacha20_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_stream_xchacha20_KEYBYTES) throw new Error('k')

  const res = binding.crypto_stream_xchacha20_xor_ic(c, m, n, ic, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_salsa20 = function (c, n, k) {
  if (n.byteLength !== binding.crypto_stream_salsa20_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_stream_salsa20_KEYBYTES) throw new Error('k')

  const res = binding.crypto_stream_salsa20(c, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_salsa20_xor = function (c, m, n, k) {
  if (c.byteLength !== m.byteLength) throw new Error('m must be "c.byteLength" bytes')
  if (n.byteLength !== binding.crypto_stream_salsa20_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_stream_salsa20_KEYBYTES) throw new Error('k')

  const res = binding.crypto_stream_salsa20_xor(c, m, n, k)

  if (res !== 0) throw new Error('status: ' + res)
}

exports.crypto_stream_salsa20_xor_ic = function (c, m, n, ic, k) {
  if (c.byteLength !== m.byteLength) throw new Error('m must be "c.byteLength" bytes')
  if (n.byteLength !== binding.crypto_stream_salsa20_NONCEBYTES) throw new Error('n')
  if (k.byteLength !== binding.crypto_stream_salsa20_KEYBYTES) throw new Error('k')

  const res = binding.crypto_stream_salsa20_xor_ic(c, m, n, ic, k)

  if (res !== 0) throw new Error('status: ' + res)
}
