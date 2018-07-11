var tape = require('tape')
var sodium = require('../')

tape('crypto_hash_sha512', function (t) {
  var out = Buffer.alloc(sodium.crypto_hash_sha512_BYTES)
  var inp = Buffer.from('Hej, Verden!')

  t.throws(function () {
    sodium.crypto_hash(Buffer.alloc(0), inp)
  }, 'throws on bad input')

  sodium.crypto_hash_sha512(out, inp)

  var result = 'bcf8e6d11dec2da6e93abb99a73c8e9c387886a5f84fbca5e25af85af26ee39161b7e0c9f9cf547f2aef40523f1aab80e26ec3c630db43ce78adc8c058dc5d16'
  t.same(out.toString('hex'), result, 'hashed the string')

  t.end()
})

tape('crypto_hash_sha256_instance', function (t) {
  var out = Buffer.alloc(sodium.crypto_hash_sha512_BYTES)
  var inp = Buffer.from('Hej, Verden!')

  var instance = sodium.crypto_hash_sha512_instance()
  instance.update(inp)
  instance.final(out)

  var result = 'bcf8e6d11dec2da6e93abb99a73c8e9c387886a5f84fbca5e25af85af26ee39161b7e0c9f9cf547f2aef40523f1aab80e26ec3c630db43ce78adc8c058dc5d16'
  t.same(out.toString('hex'), result, 'hashed the string')

  t.end()
})
