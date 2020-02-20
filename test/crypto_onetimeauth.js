var tape = require('tape')
var sodium = require('../')

tape('crypto_onetimeauth', function (t) {
  var key = Buffer.alloc(sodium.crypto_onetimeauth_KEYBYTES)
  var mac = Buffer.alloc(sodium.crypto_onetimeauth_BYTES)
  var value = Buffer.from('Hello, World!')

  sodium.randombytes_buf(key)
  sodium.crypto_onetimeauth(mac, value, key)

  t.notEqual(mac, Buffer.alloc(mac.length), 'not blank')
  t.notOk(sodium.crypto_onetimeauth_verify(Buffer.alloc(mac.length), value, key), 'does not verify')
  t.ok(sodium.crypto_onetimeauth_verify(mac, value, key), 'verifies')

  t.end()
})

tape('crypto_onetimeauth_state', function (t) {
  var key = Buffer.alloc(sodium.crypto_onetimeauth_KEYBYTES, 'lo')
  const state = Buffer.alloc(sodium.crypto_onetimeauth_STATEBYTES)

  t.throws(function () {
    sodium.crypto_onetimeauth_init(state)
  }, 'key required')

  key[0] = 42

  sodium.crypto_onetimeauth_init(state, key)
  var value = Buffer.from('Hello, World!')

  for (var i = 0; i < 10; i++) sodium.crypto_onetimeauth_update(state, value)

  var mac = Buffer.alloc(sodium.crypto_onetimeauth_BYTES)
  sodium.crypto_onetimeauth_final(state, mac)

  t.same(mac.toString('hex'), 'ac35df70e6b95051e015de11a6cbf4ab', 'streaming mac')

  t.end()
})
