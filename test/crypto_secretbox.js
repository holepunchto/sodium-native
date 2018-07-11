var tape = require('tape')
var sodium = require('../')

tape('crypto_secretbox_easy', function (t) {
  var message = Buffer.from('Hej, Verden!')
  var output = Buffer.alloc(message.length + sodium.crypto_secretbox_MACBYTES)

  var key = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)

  var nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  t.throws(function () {
    sodium.crypto_secretbox_easy(Buffer.alloc(0), message, nonce, key)
  }, 'throws if output is too small')

  t.throws(function () {
    sodium.crypto_secretbox_easy(Buffer.alloc(message.length), message, nonce, key)
  }, 'throws if output is too small')

  sodium.crypto_secretbox_easy(output, message, nonce, key)
  t.notEqual(output, Buffer.alloc(output.length))

  var result = Buffer.alloc(output.length - sodium.crypto_secretbox_MACBYTES)
  t.notOk(sodium.crypto_secretbox_open_easy(result, output, Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES), key), 'could not decrypt')
  t.ok(sodium.crypto_secretbox_open_easy(result, output, nonce, key), 'could decrypt')

  t.same(result, message, 'decrypted message is correct')

  t.end()
})

tape('crypto_secretbox_easy overwrite buffer', function (t) {
  var output = Buffer.alloc(Buffer.byteLength('Hej, Verden!') + sodium.crypto_secretbox_MACBYTES)
  output.write('Hej, Verden!', sodium.crypto_secretbox_MACBYTES)

  var key = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)

  var nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  sodium.crypto_secretbox_easy(output, output.slice(sodium.crypto_secretbox_MACBYTES), nonce, key)
  t.notEqual(output, Buffer.alloc(output.length))

  t.ok(sodium.crypto_secretbox_open_easy(output.slice(sodium.crypto_secretbox_MACBYTES), output, nonce, key), 'could decrypt')
  t.same(output.slice(sodium.crypto_secretbox_MACBYTES), Buffer.from('Hej, Verden!'), 'decrypted message is correct')

  t.end()
})

tape('crypto_secretbox_detached', function (t) {
  var message = Buffer.from('Hej, Verden!')
  var output = Buffer.alloc(message.length)
  var mac = Buffer.alloc(sodium.crypto_secretbox_MACBYTES)

  var key = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)

  var nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  sodium.crypto_secretbox_detached(output, mac, message, nonce, key)

  t.notEqual(mac, Buffer.alloc(mac.length), 'mac not blank')
  t.notEqual(output, Buffer.alloc(output.length), 'output not blank')

  var result = Buffer.alloc(output.length)

  t.notOk(sodium.crypto_secretbox_open_detached(result, output, mac, nonce, Buffer.alloc(key.length)), 'could not decrypt')
  t.ok(sodium.crypto_secretbox_open_detached(result, output, mac, nonce, key), 'could decrypt')

  t.same(result, message, 'decrypted message is correct')

  t.end()
})
