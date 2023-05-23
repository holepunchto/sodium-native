const test = require('brittle')
const sodium = require('..')

test('crypto_onetimeauth', function (t) {
  const key = Buffer.alloc(sodium.crypto_onetimeauth_KEYBYTES)
  const mac = Buffer.alloc(sodium.crypto_onetimeauth_BYTES)
  const value = Buffer.from('Hello, World!')

  sodium.randombytes_buf(key)
  sodium.crypto_onetimeauth(mac, value, key)

  t.not(mac, Buffer.alloc(mac.length), 'not blank')
  t.absent(sodium.crypto_onetimeauth_verify(Buffer.alloc(mac.length), value, key), 'does not verify')
  t.ok(sodium.crypto_onetimeauth_verify(mac, value, key), 'verifies')
})

test('crypto_onetimeauth_state', function (t) {
  const key = Buffer.alloc(sodium.crypto_onetimeauth_KEYBYTES, 'lo')
  const state = Buffer.alloc(sodium.crypto_onetimeauth_STATEBYTES)

  t.exception.all(function () {
    sodium.crypto_onetimeauth_init(state)
  }, 'key required')

  key[0] = 42

  sodium.crypto_onetimeauth_init(state, key)
  const value = Buffer.from('Hello, World!')

  for (let i = 0; i < 10; i++) sodium.crypto_onetimeauth_update(state, value)

  const mac = Buffer.alloc(sodium.crypto_onetimeauth_BYTES)
  sodium.crypto_onetimeauth_final(state, mac)

  t.alike(mac.toString('hex'), 'ac35df70e6b95051e015de11a6cbf4ab', 'streaming mac')
})
