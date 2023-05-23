const test = require('brittle')
const sodium = require('..')

test('crypto_kdf_keygen', function (t) {
  const key = Buffer.alloc(sodium.crypto_kdf_KEYBYTES)

  t.exception.all(function () {
    sodium.crypto_kdf_keygen(Buffer.alloc(1))
  })

  sodium.crypto_kdf_keygen(key)

  t.not(key, Buffer.alloc(key.length))
})

test('crypto_kdf_derive_from_key', function (t) {
  const key = Buffer.alloc(sodium.crypto_kdf_KEYBYTES)

  sodium.crypto_kdf_keygen(key)

  const subkey = Buffer.alloc(sodium.crypto_kdf_BYTES_MIN)

  sodium.crypto_kdf_derive_from_key(subkey, 0, Buffer.from('context_'), key)
  t.not(subkey, Buffer.alloc(subkey.length))

  const subkey2 = Buffer.alloc(sodium.crypto_kdf_BYTES_MIN)

  sodium.crypto_kdf_derive_from_key(subkey2, 1, Buffer.from('context_'), key)
  t.not(subkey, subkey2)

  sodium.crypto_kdf_derive_from_key(subkey2, 0, Buffer.from('context_'), key)
  t.alike(subkey, subkey2)
})
