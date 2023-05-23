const sodium = require('.')

const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
const key = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES)
const message = Buffer.from('Hello, World!')
const cipher = Buffer.alloc(message.length + sodium.crypto_secretbox_MACBYTES)

sodium.randombytes_buf(nonce) // insert random data into nonce
sodium.randombytes_buf(key) // insert random data into key

// encrypted message is stored in cipher.
sodium.crypto_secretbox_easy(cipher, message, nonce, key)

console.log('Encrypted message:', cipher)

const plainText = Buffer.alloc(cipher.length - sodium.crypto_secretbox_MACBYTES)

if (!sodium.crypto_secretbox_open_easy(plainText, cipher, nonce, key)) {
  console.log('Decryption failed!')
} else {
  console.log('Decrypted message:', plainText, '(' + plainText.toString() + ')')
}
