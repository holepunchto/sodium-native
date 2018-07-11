var tape = require('tape')
var sodium = require('../')

tape('crypto_auth', function (t) {
  var key = Buffer.alloc(sodium.crypto_auth_KEYBYTES)
  sodium.randombytes_buf(key)

  var mac = Buffer.alloc(sodium.crypto_auth_BYTES)
  var value = Buffer.from('Hej, Verden')

  sodium.crypto_auth(mac, value, key)

  t.notEqual(mac, Buffer.alloc(mac.length), 'mac not blank')
  t.notOk(sodium.crypto_auth_verify(Buffer.alloc(mac.length), value, key), 'does not verify')
  t.ok(sodium.crypto_auth_verify(mac, value, key), 'verifies')

  t.end()
})
