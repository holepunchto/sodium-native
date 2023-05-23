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

tape('test vectors', function (assert) {
  var fixtures = require('./fixtures/crypto_kdf.json')

  for (var i = 0; i < fixtures.length; i++) {
    var key = Buffer.from(fixtures[i].key, 'hex')
    var subkeyLen = fixtures[i].subkey_len
    var id = fixtures[i].id
    var context = Buffer.from(fixtures[i].context, 'hex')

    var shouldError = fixtures[i].error

    var actual = Buffer.alloc(subkeyLen)

    try {
      sodium.crypto_kdf_derive_from_key(actual, id, context, key)
      var expected = Buffer.from(fixtures[i].subkey, 'hex')
      if (Buffer.compare(actual, expected) !== 0) {
        assert.fail('Failed on fixture #' + i)
      }
    } catch (ex) {
      if (shouldError === false) assert.fail('Failed on fixture #' + i)
    }
  }

  assert.pass('Passed all fixtures')
  assert.end()
})

tape('constants', function (t) {
  t.ok(sodium.crypto_kdf_PRIMITIVE)
  t.ok(sodium.crypto_kdf_BYTES_MAX > 0)
  t.ok(sodium.crypto_kdf_BYTES_MIN <= sodium.crypto_kdf_BYTES_MAX)
  t.ok(sodium.crypto_kdf_CONTEXTBYTES > 0)
  t.ok(sodium.crypto_kdf_KEYBYTES >= 16)
  t.end()
})
