var tape = require('tape')
var sodium = require('../')

tape('crypto_kdf_keygen', function (t) {
  var key = Buffer.alloc(sodium.crypto_kdf_KEYBYTES)

  t.throws(function () {
    sodium.crypto_kdf_keygen(Buffer.alloc(1))
  })

  sodium.crypto_kdf_keygen(key)

  t.notEqual(key, Buffer.alloc(key.length))
  t.end()
})

tape('crypto_kdf_derive_from_key', function (t) {
  var key = Buffer.alloc(sodium.crypto_kdf_KEYBYTES)

  sodium.crypto_kdf_keygen(key)

  var subkey = Buffer.alloc(sodium.crypto_kdf_BYTES_MIN)

  sodium.crypto_kdf_derive_from_key(subkey, 0, Buffer.from('context_'), key)
  t.notEqual(subkey, Buffer.alloc(subkey.length))

  var subkey2 = Buffer.alloc(sodium.crypto_kdf_BYTES_MIN)

  sodium.crypto_kdf_derive_from_key(subkey2, 1, Buffer.from('context_'), key)
  t.notEqual(subkey, subkey2)

  sodium.crypto_kdf_derive_from_key(subkey2, 0, Buffer.from('context_'), key)
  t.same(subkey, subkey2)

  t.end()
})
