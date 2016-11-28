var tape = require('tape')
var alloc = require('buffer-alloc')
var sodium = require('../')

tape('crypto_onetimeauth', function (t) {
  var key = alloc(sodium.crypto_onetimeauth_KEYBYTES)
  var mac = alloc(sodium.crypto_onetimeauth_BYTES)
  var value = new Buffer('Hello, World!')

  sodium.randombytes_buf(key)
  sodium.crypto_onetimeauth(mac, value, key)

  t.notEqual(mac, alloc(mac.length), 'not blank')
  t.notOk(sodium.crypto_onetimeauth_verify(alloc(mac.length), value, key), 'does not verify')
  t.ok(sodium.crypto_onetimeauth_verify(mac, value, key), 'verifies')

  t.end()
})
