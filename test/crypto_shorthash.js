var tape = require('tape')
var sodium = require('../')

tape('crypto_shorthash', function (t) {
  var out = Buffer.alloc(sodium.crypto_shorthash_BYTES)
  var inp = Buffer.from('Hej, Verden!')
  var key = Buffer.alloc(sodium.crypto_shorthash_KEYBYTES)

  t.throws(function () {
    sodium.crypto_shorthash(Buffer.alloc(0), inp)
  }, 'throws on bad input')

  sodium.crypto_shorthash(out, inp, key)

  var result = '6a29984f782e684e'
  t.same(out.toString('hex'), result, 'hashed the string')

  t.end()
})
