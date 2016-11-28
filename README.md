# sodium-native

Low level bindings for [libsodium](https://github.com/jedisct1/libsodium).

```
npm install sodium-native
```

[![build status](https://travis-ci.org/mafintosh/sodium-native.svg?branch=master)](https://travis-ci.org/mafintosh/sodium-native)

The goal of this project is to be thin, stable, unopionated wrapper around libsodium.

All methods exposed are more or less a direct translation of the libsodium c-api.
This means that most data types are buffers and you have to manage allocating return values and passing them in as arguments intead of receiving them as return values.

This makes this API harder to use than other libsodium wrappers out there, but also means that you'll be able to get a lot of perf / memory improvements as you can do stuff like inline encryption / decryption, re-use buffers etc.

This also makes this library useful as a foundation for more high level crypto abstractions that you want to make.

## Usage

``` js
var sodium = require('sodium-native')

var nonce = new Buffer(sodium.crypto_secretbox_NONCEBYTES)
var key = new Buffer(sodium.crypto_secretbox_KEYBYTES)
var message = new Buffer('Hello, World!')
var cipher = new Buffer(message.length + sodium.crypto_secretbox_MACBYTES)

sodium.randombytes_buf(nonce) // insert random data into nonce
sodium.randombytes_buf(key)  // insert random data into key

// encrypted message is stored in cipher.
sodium.crypto_secretbox_easy(cipher, message, nonce, key)

console.log('Encrypted message:', cipher)

var plainText = new Buffer(cipher.length - sodium.crypto_secretbox_MACBYTES)

if (!sodium.crypto_secretbox_open_easy(plainText, cipher, nonce, key)) {
  console.log('Decryption failed!')
} else {
  console.log('Decrypted message:', plainText, '(' + plainText.toString() + ')')
}

```

## API

(TODO, see tests + source for now)

## License

MIT
