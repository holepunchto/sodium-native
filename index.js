const binding = require('./binding')
const { isNode } = require('which-runtime')

module.exports = binding

module.exports.sodium_malloc = function (size) {
  const buf = Buffer.from(binding._sodium_malloc(size))
  buf.secure = true
  return buf
}

module.exports.crypto_generichash = function (output, input, key = undefined) {
  return binding._crypto_generichash(output, input, !!key, key)
}

module.exports.crypto_generichash_init = function (state, key, outputLength) {
  return module.exports._crypto_generichash_init(state, !!key, key, outputLength)
}

module.exports.crypto_generichash_batch = function (output, batch, key) {
  const useKey = !!key
  if (isNode || batch.length < 12) {
    binding._crypto_generichash_batch(output, batch, useKey, key)
  } else {
    // fastcall batch
    const state = Buffer.alloc(binding.crypto_generichash_STATEBYTES)

    module.exports.crypto_generichash_init(state, key, output.byteLength)

    for (const buf of batch) {
      binding.crypto_generichash_update(state, buf)
    }

    binding.crypto_generichash_final(state, output)
  }
}

module.exports.crypto_secretstream_xchacha20poly1305_push = function (state, c, m, ad, tag) {
  return binding._crypto_secretstream_xchacha20poly1305_push(state, c, m, !!ad, ad, tag)
}

module.exports.crypto_secretstream_xchacha20poly1305_pull = function (state, m, tag, c, ad) {
  return binding._crypto_secretstream_xchacha20poly1305_pull(state, m, tag, c, !!ad, ad)
}
