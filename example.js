var sodium = require('./')
var crypto = require('crypto') // TODO: expose random from sodium :)

var nonce = crypto.randomBytes(sodium.crypto_secretbox_NONCEBYTES)
var key = crypto.randomBytes(sodium.crypto_secretbox_KEYBYTES)
var message = new Buffer('Hello, World!')
var cipher = new Buffer(message.length + sodium.crypto_secretbox_MACBYTES)

sodium.crypto_secretbox_easy(cipher, message, nonce, key)

console.log('Encrypted message:', cipher)

var plainText = new Buffer(cipher.length - sodium.crypto_secretbox_MACBYTES)

if (!sodium.crypto_secretbox_open_easy(plainText, cipher, nonce, key)) {
  console.log('Decryption failed!')
  process.exit(1)
}

console.log('Decrypted message:', plainText, '(' + plainText.toString() + ')')
