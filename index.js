// TODO: move to binding.js
require.addon = require('require-addon')
module.exports = require.addon('.', __filename)

const { isNode } = require('which-runtime')

const binding = module.exports
const _dummy = Buffer.allocUnsafeSlow(0)

module.exports.sodium_malloc = size => {
  const buf = Buffer.from(binding._sodium_malloc(size))
  buf.secure = true
  return buf
}

// fold optional argument into same typed-call signature
module.exports.crypto_generichash = function (output, input, key) {
  return binding._crypto_generichash(output, input, !!key, key || _dummy)
}

// fold optional argument into same typed-call signature
module.exports.crypto_generichash_init = function (state, key, outputLength) {
  if (state.byteLength !== binding.crypto_generichash_STATEBYTES) throw new Error("state must be 'crypto_generichash_STATEBYTES' bytes")

  const useKey = !!key
  if (useKey && key.byteLength < binding.crypto_generichash_KEYBYTES_MIN) throw new Error("key must be atleast 'crypto_generichash_KEYBYTES_MIN' bytes")
  if (useKey && key.byteLength > binding.crypto_generichash_KEYBYTES_MAX) throw new Error("key must be at most 'crypto_generichash_KEYBYTES_MAX' bytes")

  return module.exports._crypto_generichash_init(state, useKey, key || _dummy, outputLength)
}

module.exports.crypto_generichash_batch = function (output, batch, key) {
  if (true) { // isNode || batch.length < 12) {
    if (key) binding._crypto_generichash_batch(output, batch, key)
    else binding._crypto_generichash_batch(output, batch)
    return
  }

  // Levarage low-overhead native calls on bare
  const state = Buffer.alloc(binding.crypto_generichash_STATEBYTES)
  binding.crypto_generichash_init(state, key, output.byteLength)

  for (const buf of batch) {
    binding.crypto_generichash_update(state, buf)
  }

  binding.crypto_generichash_final(state, output)
}
