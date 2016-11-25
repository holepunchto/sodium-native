var tape = require('tape')
var sodium = require('../')

tape('crypto_stream', function (t) {
  var buf = new Buffer('000000000000000000')
  var nonce = random(sodium.crypto_stream_NONCEBYTES)
  var key = random(sodium.crypto_stream_KEYBYTES)

  sodium.crypto_stream(buf, nonce, key)

  t.notEquals(buf, new Buffer('000000000000000000'), 'contains noise now')
  var copy = new Buffer(buf.toString('hex'), 'hex')

  sodium.crypto_stream(buf, nonce, key)
  t.same(buf, copy, 'predictable from nonce, key')

  t.end()
})

tape('crypto_stream_xor', function (t) {
  var message = new Buffer('Hello, World!')
  var nonce = random(sodium.crypto_stream_NONCEBYTES)
  var key = random(sodium.crypto_stream_KEYBYTES)

  sodium.crypto_stream_xor(message, message, nonce, key)

  t.notEquals(message, new Buffer('Hello, World!'), 'encrypted')

  sodium.crypto_stream_xor(message, message, nonce, key)

  t.same(message, new Buffer('Hello, World!'), 'decrypted')

  t.end()
})

function random (n) {
  var buf = new Buffer(n)
  sodium.randombytes_buf(buf)
  return buf
}
