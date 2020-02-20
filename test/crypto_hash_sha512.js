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

tape('crypto_hash_sha512_state', function (t) {
  var state = Buffer.alloc(sodium.crypto_hash_sha512_STATEBYTES)
  sodium.crypto_hash_sha512_init(state)

  var buf = Buffer.from('Hej, Verden!')

  for (let i = 0; i < 10; i++) sodium.crypto_hash_sha512_update(state, buf)

  var out = Buffer.alloc(sodium.crypto_hash_sha512_BYTES)
  sodium.crypto_hash_sha512_final(state, out)

  var result = 'a0a9b965c23be41fa8c344f483da39bedcf88b7f25cdc0bc9ea335fa264dc3db51f08c1d0f5f6f0ffb08a1d8643e2a1cd0ea8f03408ca03711c751d61787a229'
  t.same(out.toString('hex'), result, 'hashed the string')

  t.end()
})
