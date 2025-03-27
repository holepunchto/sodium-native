const binding = require('./binding')
const { isNode } = require('which-runtime')

module.exports = binding

module.exports.sodium_malloc = size => {
  const buf = Buffer.from(binding._sodium_malloc(size))
  buf.secure = true
  return buf
}

module.exports.crypto_generichash = function (output, input, key = undefined) {
  return binding._crypto_generichash(output, input, key)
}

module.exports.crypto_generichash_init = function (state, key, outputLength) {
  if (state.byteLength !== binding.crypto_generichash_STATEBYTES) throw new Error("state must be 'crypto_generichash_STATEBYTES' bytes")

  key ||= undefined

  if (key) {
    if (key.byteLength < binding.crypto_generichash_KEYBYTES_MIN) throw new Error("key must be atleast 'crypto_generichash_KEYBYTES_MIN' bytes")
    if (key.byteLength > binding.crypto_generichash_KEYBYTES_MAX) throw new Error("key must be at most 'crypto_generichash_KEYBYTES_MAX' bytes")
  }

  return module.exports._crypto_generichash_init(state, key, outputLength)
}

module.exports.crypto_generichash_batch = function (output, batch, key) {
  if (isNode || batch.length < 12) {
    // native-call uses argc=(2 | 3) to detect key presence
    if (key) binding._crypto_generichash_batch(output, batch, key)
    else binding._crypto_generichash_batch(output, batch)
  } else {
    // fastcall batch
    const state = Buffer.alloc(binding.crypto_generichash_STATEBYTES)
    binding.crypto_generichash_init(state, key, output.byteLength)

    for (const buf of batch) {
      binding.crypto_generichash_update(state, buf)
    }

    binding.crypto_generichash_final(state, output)
  }
}
