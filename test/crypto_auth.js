const test = require('brittle')
const sodium = require('..')

test('crypto_auth', function (t) {
  const key = Buffer.alloc(sodium.crypto_auth_KEYBYTES)
  sodium.randombytes_buf(key)

  const mac = Buffer.alloc(sodium.crypto_auth_BYTES)
  const value = Buffer.from('Hej, Verden')

  sodium.crypto_auth(mac, value, key)

  t.not(mac, Buffer.alloc(mac.length), 'mac not blank')
  t.absent(sodium.crypto_auth_verify(Buffer.alloc(mac.length), value, key), 'does not verify')
  t.ok(sodium.crypto_auth_verify(mac, value, key), 'verifies')
})
