require.addon = require('require-addon')
module.exports = require.addon('.', __filename)

const _dummy = Buffer.allocUnsafeSlow(0)

// fold w/ and w/o key into the same typed-call signature for fast lane
module.exports.crypto_generichash = function (output, input, key) {
  return module.exports._crypto_generichash(output, input, !!key, key || _dummy)
}

module.exports.sodium_malloc = size => {
  const buf = Buffer.from(module.exports._sodium_malloc(size))
  buf.secure = true
  return buf
}
