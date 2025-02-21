require.addon = require('require-addon')
module.exports = require.addon('.', __filename)

module.exports.sodium_malloc = size => {
  const buf = Buffer.from(module.exports._sodium_malloc(size))
  buf.secure = true
  return buf
}
