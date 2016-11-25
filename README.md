# sodium-native

Low level bindings for libsodium (WIP, HERE BE DRAGONS).

```
npm install sodium-native
```

[![build status](https://travis-ci.org/mafintosh/sodium-native.svg?branch=master)](https://travis-ci.org/mafintosh/sodium-native)

## Usage

``` js
var sodium = require('sodium-native')

var nonce = new Buffer(sodium.crypto_secretbox_NONCEBYTES)
var key = new Buffer(sodium.crypto_secretbox_KEYBYTES)
var message = new Buffer('Hello, World!')
var cipher = new Buffer(message.length + sodium.crypto_secretbox_MACBYTES)

sodium.randombytes_buf(nonce)
sodium.randombytes_buf(key)
sodium.crypto_secretbox_easy(cipher, message, nonce, key)

console.log('Encrypted message:', cipher)

var plainText = new Buffer(cipher.length - sodium.crypto_secretbox_MACBYTES)

if (!sodium.crypto_secretbox_open_easy(plainText, cipher, nonce, key)) {
  console.log('Decryption failed!')
  process.exit(1)
}

console.log('Decrypted message:', plainText, '(' + plainText.toString() + ')')
```

## API

(TODO, see tests + source for now)

## License

MIT
