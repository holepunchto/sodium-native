var bindings = require('bindings')
var sodium = bindings('sodium')

var pk = new Buffer(sodium.crypto_sign_PUBLICKEYBYTES)
var sk = new Buffer(sodium.crypto_sign_SECRETKEYBYTES)
var seed = new Buffer(sodium.crypto_sign_SEEDBYTES).fill('yolo')

console.log('crypto_sign_seed_keypair()', sodium.crypto_sign_seed_keypair(pk, sk, seed))

var message = new Buffer('Hello, World!')
var signedMessage = new Buffer(sodium.crypto_sign_BYTES + message.length)

console.log('crypto_sign()', sodium.crypto_sign(signedMessage, message, sk))

var rawMessage = new Buffer(message.length)

console.log('crypto_sign_open()', sodium.crypto_sign_open(rawMessage, signedMessage, pk))

console.log('-->', rawMessage.toString())

var rawSignature = new Buffer(sodium.crypto_sign_BYTES)

console.log('crypto_sign_detached()', sodium.crypto_sign_detached(rawSignature, message, sk))

console.log('crypto_sign_verify_detached()', sodium.crypto_sign_verify_detached(rawSignature, message, pk))
