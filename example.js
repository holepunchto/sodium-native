var sodium = require('./')

var publicKey = new Buffer(sodium.crypto_sign_PUBLICKEYBYTES)
var secretKey = new Buffer(sodium.crypto_sign_SECRETKEYBYTES)

sodium.crypto_sign_keypair(publicKey, secretKey)

console.log('public-key:', publicKey)
console.log('secret-key:', secretKey)
