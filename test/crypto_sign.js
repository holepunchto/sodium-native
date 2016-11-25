var tape = require('tape')
var sodium = require('../')

tape('crypto_sign_seed_keypair', function (t) {
  var pk = new Buffer(sodium.crypto_sign_PUBLICKEYBYTES)
  var sk = new Buffer(sodium.crypto_sign_SECRETKEYBYTES)
  var seed = new Buffer(sodium.crypto_sign_SEEDBYTES)

  seed.fill('lo')

  t.throws(function () {
    sodium.crypto_sign_seed_keypair()
  }, 'should validate input')

  t.throws(function () {
    sodium.crypto_sign_seed_keypair(new Buffer(0), new Buffer(0), new Buffer(0))
  }, 'should validate input length')

  sodium.crypto_sign_seed_keypair(pk, sk, seed)

  var eSk = '6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f41eb5b4dba29b19e391d9a4d1a4a879b27958ff3734e10cfbf1f46d68f4d3038'
  var ePk = '41eb5b4dba29b19e391d9a4d1a4a879b27958ff3734e10cfbf1f46d68f4d3038'

  t.same(pk.toString('hex'), ePk, 'seeded public key')
  t.same(sk.toString('hex'), eSk, 'seeded secret key')
  t.end()
})

tape('crypto_sign_keypair', function (t) {
  var pk = blank(sodium.crypto_sign_PUBLICKEYBYTES)
  var sk = blank(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_keypair(pk, sk)

  t.notEqual(pk, blank(pk.length), 'made public key')
  t.notEqual(sk, blank(sk.length), 'made secret key')

  t.throws(function () {
    sodium.crypto_sign_keypair()
  }, 'should validate input')

  t.throws(function () {
    sodium.crypto_sign_keypair(new Buffer(0), new Buffer(0))
  }, 'should validate input length')

  t.end()
})

tape('crypto_sign', function (t) {
  var pk = new Buffer(sodium.crypto_sign_PUBLICKEYBYTES)
  var sk = new Buffer(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_keypair(pk, sk)

  var message = new Buffer('hello world')
  var signedMessage = new Buffer(message.length + sodium.crypto_sign_BYTES)

  sodium.crypto_sign(signedMessage, message, sk)

  t.same(signedMessage.slice(-message.length), message, 'contains message')

  var output = new Buffer(message.length)

  t.notOk(sodium.crypto_sign_open(output, Buffer.concat([blank(1), signedMessage]), pk), 'was not signed')
  t.ok(sodium.crypto_sign_open(output, signedMessage, pk), 'was signed')

  t.same(output, message, 'same message')
  t.end()
})

tape('crypto_sign_detached', function (t) {
  var pk = new Buffer(sodium.crypto_sign_PUBLICKEYBYTES)
  var sk = new Buffer(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_keypair(pk, sk)

  var message = new Buffer('hello world')
  var signature = new Buffer(sodium.crypto_sign_BYTES)

  sodium.crypto_sign_detached(signature, message, sk)

  t.notOk(sodium.crypto_sign_verify_detached(Buffer.concat([blank(1), signature]), message, pk), 'was not signed')
  t.ok(sodium.crypto_sign_verify_detached(signature, message, pk), 'was signed')

  t.end()
})

function blank (n) {
  var buf = new Buffer(n)
  buf.fill(0)
  return buf
}
