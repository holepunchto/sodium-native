# sodium-native

Low level bindings for [libsodium](https://github.com/jedisct1/libsodium).

```
npm install sodium-native
```

[![build status](https://travis-ci.org/sodium-friends/sodium-native.svg?branch=master)](https://travis-ci.org/sodium-friends/sodium-native)
[![build status](https://ci.appveyor.com/api/projects/status/8wi3my2clf1ami6k/branch/master?svg=true)](https://ci.appveyor.com/project/mafintosh/sodium-native/branch/master)


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

#### `var sodium = require('sodium-native')`

Loads the bindings. If you get an module version error you probably need to reinstall the module because you switched node versions.

### Generating random data

Bindings to the random data generation API.
[See the libsodium randombytes_buf docs for more information](https://download.libsodium.org/doc/generating_random_data/).

#### `sodium.randombytes_buf(buffer)`

Fill `buffer` with random data.

### Signing

Bindings for the crypto_sign API.
[See the libsodium crypto_sign docs for more information](https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html).

#### `crypto_sign_seed_keypair(publicKey, secretKey, seed)`

Create a new keypair based on a seed.

* `publicKey` should be a buffer with length `crypto_sign_PUBLICKEYBYTES`.
* `secretKey` should be a buffer with length `crypto_sign_SECRETKEYBYTES`.
* `seed` should be a buffer with length `crypto_sign_SEEDBYTES`.

The generated public and secret key will be stored in passed in buffers.

#### `crypto_sign_keypair(publicKey, secretKey)`

Create a new keypair.

* `publicKey` should be a buffer with length `crypto_sign_PUBLICKEYBYTES`.
* `secretKey` should be a buffer with length `crypto_sign_SECRETKEYBYTES`.

The generated public and secret key will be stored in passed in buffers.

#### `crypto_sign(signedMessage, message, secretKey)`

Sign a message.

* `signedMessage` should be a buffer with length `crypto_sign_BYTES + message.length`.
* `message` should be a buffer of any length.
* `secretKey` should be a secret key.

The generated signed message will be stored in `signedMessage`.

#### `var bool = crypto_sign_open(message, signedMessage, publicKey)`

Verify and open a message.

* `message` should be a buffer with length `signedMessage - crypto_sign_BYTES`.
* `signedMessage` at least `crypto_sign_BYTES` length.
* `publicKey` should be a public key.

Will return `true` if the message could be verified. Otherwise `false`.
If verified the originally signed message is stored in the `message` buffer.

#### `crypto_sign_detached(signature, message, secretKey)`

Same as `crypto_sign` except it only stores the signature.

* `signature` should be a buffer with length `crypto_sign_BYTES`.
* `message` should be a buffer of any length.
* `secretKey` should be a secret key.

The generated signature is stored in `signature`.

#### `var bool = crypto_sign_verify_detached(signature, message, publicKey)`

Verify a signature.

* `signature` should be a buffer with length `crypto_sign_BYTES`.
* `message` should be a buffer of any length.
* `publicKey` should be a public key.

Will return `true` if the message could be verified. Otherwise `false`.

### Generic hashing

Bindings for the crypto_generichash API.
[See the libsodium crypto_generichash docs for more information](https://download.libsodium.org/doc/hashing/generic_hashing.html).

#### `crypto_generichash(output, input, [key])`

Hash a value with an optional key using the generichash method.

* `output` should be a buffer with length within `crypto_generichash_BYTES_MIN` - `crypto_generichash_BYTES_MAX`.
* `input` should be a buffer of any length.
* `key` is an optional buffer of length within `crypto_generichash_KEYBYTES_MIN` - `crypto_generichash_KEYBYTES_MAX`.

The generated hash is stored in `output`.

Also exposes `crypto_generichash_BYTES` and `crypto_generichash_KEYBYTES` that can be used as "default" buffer sizes.

#### `crypto_generichash_batch(output, inputArray, [key])`

Same as `crypto_generichash` except this hashes an array of buffers instead of a single one.

#### `var instance = crypto_generichash_instance([key], [outputLength])`

Create a generichash instance that can hash a stream of input buffers.

* `key` is an optional buffer as above.
* `outputLength` the buffer size of your output.

#### `instance.update(input)`

Update the instance with a new piece of data.

* `input` should be a buffer of any size.

#### `instance.final(output)`

Finalize the instance.

* `output` should be a buffer as above with the same length you gave when creating the instance.

The generated hash is stored in `output`.

### Public / secret key box encryption

Bindings for the crypto_box API.
[See the libsodium crypto_box docs for more information](https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html).

#### `crypto_box_seed_keypair(publicKey, secretKey, seed)`

Create a new keypair based on a seed.

* `publicKey` should be a buffer with length `crypto_box_PUBLICKEYBYTES`.
* `secretKey` should be a buffer with length `crypto_box_SECRETKEYBYTES`.
* `seed` should be a buffer with length `crypto_box_SEEDBYTES`.

The generated public and secret key will be stored in passed in buffers.

#### `crypto_box_keypair(publicKey, secretKey)`

Create a new keypair.

* `publicKey` should be a buffer with length `crypto_box_PUBLICKEYBYTES`.
* `secretKey` should be a buffer with length `crypto_box_SECRETKEYBYTES`.

The generated public and secret key will be stored in passed in buffers.

#### `crypto_box_detached(cipher, mac, message, nonce, publicKey, secretKey)`

Encrypt a message.

* `cipher` should be a buffer with length `message.length`.
* `mac` should be a buffer with length `crypto_box_MACBYTES`.
* `message` should be a buffer of any length.
* `nonce` should be a buffer with length `crypto_box_NONCEBYTES`.
* `publicKey` should be a public key.
* `secretKey` should be a secret key.

The encrypted message will be stored in `cipher` and the authentification code will be stored in `mac`.

#### `crypto_box_easy(cipher, message, nonce, publicKey, secretKey)`

Same as `crypto_box_detached` except it encodes the mac in the message.

* `cipher` should be a buffer with length `message.length + crypto_box_MACBYTES`.
* `message` should be a buffer of any length.
* `nonce` should be a buffer with length `crypto_box_NONCEBYTES`.
* `publicKey` should be a public key.
* `secretKey` should be a secret key.

The encrypted message and authentification code  will be stored in `cipher`.

#### `var bool = crypto_box_open_detached(message, cipher, mac, nonce, publicKey, secretKey)`

Decrypt a message.

* `message` should be a buffer with length `cipher.length`.
* `mac` should be a buffer with length `crypto_box_MACBYTES`.
* `cipher` should be a buffer of any length.
* `nonce` should be a buffer with length `crypto_box_NONCEBYTES`.
* `publicKey` should be a public key.
* `secretKey` should be a secret key.

Returns `true` if the message could be decrypted. Otherwise `false`.

The decrypted message will be stored in `message`.

#### `var bool = crypto_box_open_easy(message, cipher, nonce, publicKey, secretKey)`

Decrypt a message encoded with the easy method.

* `message` should be a buffer with length `cipher.length`.
* `cipher` should be a buffer with length at least `crypto_box_MACBYTES`.
* `nonce` should be a buffer with length `crypto_box_NONCEBYTES`.
* `publicKey` should be a public key.
* `secretKey` should be a secret key.

Returns `true` if the message could be decrypted. Otherwise `false`.

The decrypted message will be stored in `message`.

### Secret key box encryption

Bindings for the crypto_secretbox API.
[See the libsodium crypto_secretbox docs for more information](https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html).

#### `crypto_secretbox_detached(cipher, mac, message, nonce, secretKey)`

Encrypt a message.

* `cipher` should be a buffer with length `message.length`.
* `mac` should be a buffer with length `crypto_secretbox_MACBYTES`.
* `message` should be a buffer of any length.
* `nonce` should be a buffer with length `crypto_secretbox_NONCEBYTES`.
* `secretKey` should be a secret key with legnth `crypto_secretbox_KEYBYTES`.

The encrypted message will be stored in `cipher` and the authentification code will be stored in `mac`.

#### `crypto_secretbox_easy(cipher, message, nonce, secretKey)`

Same as `crypto_secretbox_detached` except it encodes the mac in the message.

* `cipher` should be a buffer with length `message.length + crypto_secretbox_MACBYTES`.
* `message` should be a buffer of any length.
* `nonce` should be a buffer with length `crypto_secretbox_NONCEBYTES`.
* `secretKey` should be a secret key with legnth `crypto_secretbox_KEYBYTES`.

#### `var bool = crypto_secretbox_open_detached(message, cipher, mac, nonce, secretKey)`

Decrypt a message.

* `message` should be a buffer with length `cipher.length`.
* `mac` should be a buffer with length `crypto_secretbox_MACBYTES`.
* `cipher` should be a buffer of any length.
* `nonce` should be a buffer with length `crypto_secretbox_NONCEBYTES`.
* `secretKey` should be a secret key.

Returns `true` if the message could be decrypted. Otherwise `false`.

The decrypted message will be stored in `message`.

#### `var bool = crypto_secretbox_open_easy(message, cipher, nonce, secretKey)`

Decrypt a message encoded with the easy method.

* `message` should be a buffer with length `cipher.length`.
* `cipher` should be a buffer with length at least `crypto_secretbox_MACBYTES`.
* `nonce` should be a buffer with length `crypto_secretbox_NONCEBYTES`.
* `secretKey` should be a secret key.

Returns `true` if the message could be decrypted. Otherwise `false`.

The decrypted message will be stored in `message`.

### Non-authenticated streaming encryption

Bindings for the crypto_stream API.
[See the libsodium crypto_stream docs for more information](https://download.libsodium.org/doc/advanced/xsalsa20.html).

#### `crypto_stream(cipher, nonce, key)`

Generate random data based on a nonce and key into the cipher.

* `cipher` should be a buffer of any size.
* `nonce` should be a buffer with length `crypto_stream_NONCEBYTES`.
* `key` should be a secret key with length `crypto_stream_KEYBYTES`.

The generated data is stored in `cipher`.

#### `crypto_stream_xor(cipher, message, nonce, key)` or
#### `crypto_stream_chacha20_xor(cipher, message, nonce, key)`

Encrypt, but *not* authenticate, a message based on a nonce and key

* `cipher` should be a buffer with length `message.length`.
* `message` should be a buffer of any size.
* `nonce` should be a buffer with length `crypto_stream_NONCEBYTES`.
* `key` should be a secret key with length `crypto_stream_KEYBYTES`.

The encrypted data is stored in `cipher`. To decrypt, swap `cipher` and `message`.
Also supports in-place encryption where you use the same buffer as `cipher` and `message`.

Encryption defaults to XSalsa20, use `crypto_stream_chacha20_xor` if you want
to encrypt/decrypt with ChaCha20 instead.

#### `var instance = crypto_stream_xor_instance(nonce, key)` or
#### `var instance = crypto_stream_chacha20_xor_instance(nonce, key)`

A streaming instance to the `crypto_stream_xor` api. Pass a nonce and key in the constructor.

Encryption defaults to XSalsa20, use `crypto_stream_chacha20_xor_instance` if
you want to encrypt/decrypt with ChaCha20 instead.

#### `instance.update(cipher, message)`

Encrypt the next message

#### `instance.final()`

Finalize the stream. Zeros out internal state.

### Authentication

Bindings for the crypto_auth API.
[See the libsodium crypto_auth docs for more information](https://download.libsodium.org/doc/secret-key_cryptography/secret-key_authentication.html).

#### `crypto_auth(output, input, key)`

Create an authentication token.

* `output` should be a buffer of length `crypto_auth_BYTES`.
* `input` should be a buffer of any size.
* `key` should be a buffer of lenght `crypto_auth_KEYBYTES`.

The generated token is stored in `output`.

#### `var bool = crypto_auth_verify(output, input, key)`

Verify a token.

* `output` should be a buffer of length `crypto_auth_BYTES`.
* `input` should be a buffer of any size.
* `key` should be a buffer of lenght `crypto_auth_KEYBYTES`.

Returns `true` if the token could be verified. Otherwise `false`.

### One-time Authentication

Bindings for the crypto_onetimeauth API.
[See the libsodium crypto_onetimeauth docs for more information](https://download.libsodium.org/doc/advanced/poly1305.html).

#### `crypto_onetimeauth(output, input, key)`

Create a authentication token based on a onetime key.

* `output` should be a buffer of length `crypto_onetimauth_BYTES`.
* `input` should be a buffer of any size.
* `key` should be a buffer of lenght `crypto_onetimeauth_KEYBYTES`.

The generated token is stored in `output`.

#### `var bool = crypto_onetimeauth_verify(output, input, key)`

Verify a token.

* `output` should be a buffer of length `crypto_onetimeauth_BYTES`.
* `input` should be a buffer of any size.
* `key` should be a buffer of lenght `crypto_onetimeauth_KEYBYTES`.

Returns `true` if the token could be verified. Otherwise `false`.

#### `var instance = crypto_onetimeauth_instance(key)`

Create an instance that create a token from a onetime key and a stream of input data.

* `key` should be a buffer of length `crypto_onetimeauth_KEYBYTES`.

#### `instance.update(input)`

Update the instance with a new piece of data.

* `input` should be a buffer of any size.

#### `instance.final(output)`

Finalize the instance.

* `output` should be a buffer of length `crypto_onetimeauth_BYTES`.

The generated hash is stored in `output`.

### Password Hashing

Bindings for the crypto_pwhash API.
[See the libsodium crypto_pwhash docs for more information](https://download.libsodium.org/doc/password_hashing/).

#### `crypto_pwhash(output, password, salt, opslimit, memlimit, algorithm)`

Create a password hash.

* `output` should be a buffer with length within `crypto_pwhash_BYTES_MIN` - `crypto_pwhash_BYTES_MAX`.
* `password` should be a buffer of any size.
* `salt` should be a buffer with length `crypto_passwd_SALTBYTES`.
* `opslimit` should a be number containing your ops limit setting in the range `crypto_pwhash_OPSLIMIT_MIN` - `crypto_pwhash_OPSLIMIT_MAX`.
* `memlimit` should a be number containing your mem limit setting in the range `crypto_pwhash_MEMLIMIT_MIN` - `crypto_pwhash_OPSLIMIT_MAX`.
* `algorithm` should be a number specifying the algorithm you want to use.

Available default ops and mem limits are

* `crypto_pwhash_OPSLIMIT_INTERACTIVE`
* `crypto_pwhash_OPSLIMIT_MODERATE`
* `crypto_pwhash_OPSLIMIT_SENSITIVE`
* `crypto_pwhash_MEMLIMIT_INTERACTIVE`
* `crypto_pwhash_MEMLIMIT_MODERATE`
* `crypto_pwhash_MEMLIMIT_SENSITIVE`

The available algorithms are

* `crypto_pwhash_ALG_DEFAULT`

The generated hash will be stored in `output` and the entire `output` buffer will be used.

#### `crypto_pwhash_str(output, password, opslimit, memlimit)`

Create a password hash with a random salt.

* `output` should be a buffer with length `crypto_pwhash_STRBYTES`.
* `password` should be a buffer of any size.
* `opslimit` should a be number containing your ops limit setting in the range `crypto_pwhash_OPSLIMIT_MIN` - `crypto_pwhash_OPSLIMIT_MAX`.
* `memlimit` should a be number containing your mem limit setting in the range `crypto_pwhash_MEMLIMIT_MIN` - `crypto_pwhash_OPSLIMIT_MAX`.

The generated hash, settings, salt, version and algorithm will be stored in `output` and the entire `output` buffer will be used.

#### `var bool = crypto_pwhash_str_verify(str, password)`

Verify a password hash generated with the above method.

* `str` should be a buffer with length `crypto_pwhash_STRBYTES`.
* `password` should be a buffer of any size.

Returns `true` if the hash could be verified with the settings contained in `str`. Otherwise `false`.

### Scalar multiplication

Bindings for the crypto_scalarmult API.
[See the libsodium crypto_scalarmult docs for more information](https://download.libsodium.org/doc/advanced/scalar_multiplication.html).

#### `crypto_scalarmult_base(publicKey, secretKey)`

Create a scalar multiplication public key based on a secret key

* `publicKey` should be a buffer of length `crypto_scalarmult_BYTES`.
* `secretKey` should be a buffer of length `crypto_scalarmult_SCALARBYTES`.

The generated public key is stored in `publicKey`.

#### `crypto_scalarmult(sharedSecret, secretKey, remotePublicKey)`

Derive a shared secret from a local secret key and a remote public key.

* `sharedSecret` shoudl be a buffer of length `crypto_scalarmult_BYTES`.
* `secretKey` should be a buffer of length `crypto_scalarmult_SCALARBYTES`.
* `remotePublicKey` should be a buffer of length `crypto_scalarmult_BYTES`.

The generated shared secret is stored in `sharedSecret`.

### Short hashes

Bindings for the crypto_shorthash API.
[See the libsodium crypto_shorthash docs for more information](https://download.libsodium.org/doc/hashing/short-input_hashing.html).

#### `crypto_shorthash(output, input, key)`

Hash a value to a short hash based on a key.

* `output` should be a buffer of length `crypto_shorthash_BYTES`.
* `input` should be a buffer of any size.
* `key` should be a buffer of length `crypto_shorthash_KEYBYTES`.

The generated short hash is stored in `output`.

### Key derivation

Bindings for the crypto_kdf API.
[See the libsodium crypto_kdf docs for more information](https://download.libsodium.org/doc/key_derivation/).

#### `crypto_kdf_keygen(key)`

Generate a new master key.

* `key` should be a buffer of length `crypto_kdf_KEYBYTES`

#### `crypto_kdf_derive_from_key(subkey, subkeyId, context, key)`

Derive a new key from a master key.

* `subkey` should be a buffer between `crypto_kdf_BYTES_MIN` and `crypto_kdf_BYTES_MAX`.
* `subkeyId` should be an integer.
* `context` should be a buffer of length `crypto_kdf_CONTEXTBYTES`
* `key` should by a buffer of length `crypto_kdf_KEYBYTES`

### SHA

#### `crypto_hash_sha256(output, input)`

Hash a value to a short hash based on a key.

* `output` should be a buffer of length `crypto_hash_sha256_BYTES`.
* `input` should be a buffer of any size.

The generated short hash is stored in `output`.

#### `var instance = crypto_hash_sha256_instance()`

Create an instance that has stream of input data to sha256.

#### `instance.update(input)`

Update the instance with a new piece of data.

* `input` should be a buffer of any size.

#### `instance.final(output)`

Finalize the instance.

* `output` should be a buffer of length `crypto_hash_sha256_BYTES`.

The generated hash is stored in `output`.

#### `crypto_hash_sha512(output, input)`

Hash a value to a short hash based on a key.

* `output` should be a buffer of length `crypto_hash_sha512_BYTES`.
* `input` should be a buffer of any size.

The generated short hash is stored in `output`.

#### `var instance = crypto_hash_sha512_instance()`

Create an instance that has stream of input data to sha512.

#### `instance.update(input)`

Update the instance with a new piece of data.

* `input` should be a buffer of any size.

#### `instance.final(output)`

Finalize the instance.

* `output` should be a buffer of length `crypto_hash_sha512_BYTES`.

The generated hash is stored in `output`.

## License

MIT
