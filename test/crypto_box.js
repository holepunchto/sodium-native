var tape = require('tape')
var sodium = require('../')

tape('crypto_box_seed_keypair', function (t) {
  var pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  var sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)
  var seed = Buffer.alloc(sodium.crypto_box_SEEDBYTES, 'lo')

  t.throws(function () {
    sodium.crypto_box_seed_keypair()
  }, 'should validate input')

  t.throws(function () {
    sodium.crypto_box_seed_keypair(new Buffer(0), new Buffer(0), new Buffer(0))
  }, 'should validate input length')

  sodium.crypto_box_seed_keypair(pk, sk, seed)

  var eSk = '8661a95d21b134adc02881022ad86d37f32a230d537b525b997bce27aa745afc'
  var ePk = '425c5ba523e70411c77300bb48dd846562e6c1fcf0142d81d2567d650ce76c3b'

  t.same(pk.toString('hex'), ePk, 'seeded public key')
  t.same(sk.toString('hex'), eSk, 'seeded secret key')
  t.end()
})

tape('crypto_box_keypair', function (t) {
  var pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  var sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)

  sodium.crypto_box_keypair(pk, sk)

  t.notEqual(pk, Buffer.alloc(pk.length), 'made public key')
  t.notEqual(sk, Buffer.alloc(sk.length), 'made secret key')

  t.throws(function () {
    sodium.crypto_box_keypair()
  }, 'should validate input')

  t.throws(function () {
    sodium.crypto_box_keypair(new Buffer(0), new Buffer(0))
  }, 'should validate input length')

  t.end()
})

tape('crypto_box_detached', function (t) {
  var pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  var sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)
  var nonce = Buffer.alloc(sodium.crypto_box_NONCEBYTES)

  sodium.crypto_box_keypair(pk, sk)

  var message = new Buffer('Hello, World!')
  var mac = Buffer.alloc(sodium.crypto_box_MACBYTES)
  var cipher = Buffer.alloc(message.length)

  sodium.crypto_box_detached(cipher, mac, message, nonce, pk, sk)

  t.notEqual(cipher, Buffer.alloc(cipher.length), 'not blank')

  var plain = Buffer.alloc(cipher.length)
  t.notOk(sodium.crypto_box_open_detached(plain, cipher, Buffer.alloc(mac.length), nonce, pk, sk), 'does not decrypt')
  t.ok(sodium.crypto_box_open_detached(plain, cipher, mac, nonce, pk, sk), 'decrypts')
  t.same(plain, message, 'same message')

  t.end()
})

tape('crypto_box_easy', function (t) {
  var pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  var sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)
  var nonce = Buffer.alloc(sodium.crypto_box_NONCEBYTES)

  sodium.crypto_box_keypair(pk, sk)

  var message = new Buffer('Hello, World!')
  var cipher = Buffer.alloc(message.length + sodium.crypto_box_MACBYTES)

  sodium.crypto_box_easy(cipher, message, nonce, pk, sk)

  t.notEqual(cipher, Buffer.alloc(cipher.length), 'not blank')

  var plain = Buffer.alloc(cipher.length - sodium.crypto_box_MACBYTES)
  t.notOk(sodium.crypto_box_open_easy(plain, Buffer.alloc(cipher.length), nonce, pk, sk), 'does not decrypt')
  t.ok(sodium.crypto_box_open_easy(plain, cipher, nonce, pk, sk), 'decrypts')
  t.same(plain, message, 'same message')

  t.end()
})

tape('crypto_box_seal', function (t) {
  var pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  var sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)

  sodium.crypto_box_keypair(pk, sk)

  var pk2 = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  var sk2 = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)

  sodium.crypto_box_keypair(pk2, sk2)

  var message = new Buffer('Hello, sealed World!')
  var cipher = Buffer.alloc(message.length + sodium.crypto_box_SEALBYTES)

  sodium.crypto_box_seal(cipher, message, pk)
  t.notEqual(cipher, message, 'did not encrypt!')

  t.notEqual(cipher, Buffer.alloc(cipher.length), 'not blank')

  var plain = Buffer.alloc(cipher.length - sodium.crypto_box_SEALBYTES)
  t.notOk(sodium.crypto_box_seal_open(plain, cipher, pk2, sk2), 'does not decrypt')
  t.ok(sodium.crypto_box_seal_open(plain, cipher, pk, sk), 'decrypts')
  t.same(plain, message, 'same message')

  t.end()
})
