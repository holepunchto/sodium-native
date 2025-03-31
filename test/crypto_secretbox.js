const test = require('brittle')
const sodium = require('..')

test('crypto_secretbox_easy', function (t) {
  const message = Buffer.from('Hej, Verden!')
  const output = Buffer.alloc(message.length + sodium.crypto_secretbox_MACBYTES)

  const key = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)

  const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  t.exception.all(function () {
    sodium.crypto_secretbox_easy(Buffer.alloc(0), message, nonce, key)
  }, 'throws if output is too small')

  t.exception.all(function () {
    sodium.crypto_secretbox_easy(Buffer.alloc(message.length), message, nonce, key)
  }, 'throws if output is too small')

  sodium.crypto_secretbox_easy(output, message, nonce, key)
  t.not(output, Buffer.alloc(output.length))

  const result = Buffer.alloc(output.length - sodium.crypto_secretbox_MACBYTES)
  t.absent(sodium.crypto_secretbox_open_easy(result, output, Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES), key), 'could not decrypt')
  t.ok(sodium.crypto_secretbox_open_easy(result, output, nonce, key), 'could decrypt')

  t.alike(result, message, 'decrypted message is correct')
})

test('crypto_secretbox_easy overwrite buffer', function (t) {
  const output = Buffer.alloc(Buffer.byteLength('Hej, Verden!') + sodium.crypto_secretbox_MACBYTES)
  output.write('Hej, Verden!', sodium.crypto_secretbox_MACBYTES)

  const key = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)

  const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  sodium.crypto_secretbox_easy(output, output.subarray(sodium.crypto_secretbox_MACBYTES), nonce, key)
  t.not(output, Buffer.alloc(output.length))

  t.ok(sodium.crypto_secretbox_open_easy(output.subarray(sodium.crypto_secretbox_MACBYTES), output, nonce, key), 'could decrypt')
  t.alike(output.subarray(sodium.crypto_secretbox_MACBYTES), Buffer.from('Hej, Verden!'), 'decrypted message is correct')
})

test('crypto_secretbox_detached', function (t) {
  const message = Buffer.from('Hej, Verden!')
  const output = Buffer.alloc(message.length)
  const mac = Buffer.alloc(sodium.crypto_secretbox_MACBYTES)

  const key = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)

  const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  sodium.crypto_secretbox_detached(output, mac, message, nonce, key)

  t.not(mac, Buffer.alloc(mac.length), 'mac not blank')
  t.not(output, Buffer.alloc(output.length), 'output not blank')

  const result = Buffer.alloc(output.length)

  t.absent(sodium.crypto_secretbox_open_detached(result, output, mac, nonce, Buffer.alloc(key.length)), 'could not decrypt')
  t.ok(sodium.crypto_secretbox_open_detached(result, output, mac, nonce, key), 'could decrypt')

  t.alike(result, message, 'decrypted message is correct')
})
