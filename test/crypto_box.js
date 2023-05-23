const test = require('brittle')
const sodium = require('..')

test('crypto_box_seed_keypair', function (t) {
  const pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)
  const seed = Buffer.alloc(sodium.crypto_box_SEEDBYTES, 'lo')

  t.exception.all(function () {
    sodium.crypto_box_seed_keypair()
  }, 'should validate input')

  t.exception.all(function () {
    sodium.crypto_box_seed_keypair(Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0))
  }, 'should validate input length')

  sodium.crypto_box_seed_keypair(pk, sk, seed)

  const eSk = '8661a95d21b134adc02881022ad86d37f32a230d537b525b997bce27aa745afc'
  const ePk = '425c5ba523e70411c77300bb48dd846562e6c1fcf0142d81d2567d650ce76c3b'

  t.alike(pk.toString('hex'), ePk, 'seeded public key')
  t.alike(sk.toString('hex'), eSk, 'seeded secret key')
})

test('crypto_box_keypair', function (t) {
  const pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)

  sodium.crypto_box_keypair(pk, sk)

  t.not(pk, Buffer.alloc(pk.length), 'made public key')
  t.not(sk, Buffer.alloc(sk.length), 'made secret key')

  t.exception.all(function () {
    sodium.crypto_box_keypair()
  }, 'should validate input')

  t.exception.all(function () {
    sodium.crypto_box_keypair(Buffer.alloc(0), Buffer.alloc(0))
  }, 'should validate input length')
})

test('crypto_box_detached', function (t) {
  const pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)
  const nonce = Buffer.alloc(sodium.crypto_box_NONCEBYTES)

  sodium.crypto_box_keypair(pk, sk)

  const message = Buffer.from('Hello, World!')
  const mac = Buffer.alloc(sodium.crypto_box_MACBYTES)
  const cipher = Buffer.alloc(message.length)

  sodium.crypto_box_detached(cipher, mac, message, nonce, pk, sk)

  t.not(cipher, Buffer.alloc(cipher.length), 'not blank')

  const plain = Buffer.alloc(cipher.length)
  t.absent(sodium.crypto_box_open_detached(plain, cipher, Buffer.alloc(mac.length), nonce, pk, sk), 'does not decrypt')
  t.ok(sodium.crypto_box_open_detached(plain, cipher, mac, nonce, pk, sk), 'decrypts')
  t.alike(plain, message, 'same message')
})

test('crypto_box_easy', function (t) {
  const pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)
  const nonce = Buffer.alloc(sodium.crypto_box_NONCEBYTES)

  sodium.crypto_box_keypair(pk, sk)

  const message = Buffer.from('Hello, World!')
  const cipher = Buffer.alloc(message.length + sodium.crypto_box_MACBYTES)

  sodium.crypto_box_easy(cipher, message, nonce, pk, sk)

  t.not(cipher, Buffer.alloc(cipher.length), 'not blank')

  const plain = Buffer.alloc(cipher.length - sodium.crypto_box_MACBYTES)
  t.absent(sodium.crypto_box_open_easy(plain, Buffer.alloc(cipher.length), nonce, pk, sk), 'does not decrypt')
  t.ok(sodium.crypto_box_open_easy(plain, cipher, nonce, pk, sk), 'decrypts')
  t.alike(plain, message, 'same message')
})

test('crypto_box_seal', function (t) {
  const pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)

  sodium.crypto_box_keypair(pk, sk)

  const pk2 = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  const sk2 = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)

  sodium.crypto_box_keypair(pk2, sk2)

  const message = Buffer.from('Hello, sealed World!')
  const cipher = Buffer.alloc(message.length + sodium.crypto_box_SEALBYTES)

  sodium.crypto_box_seal(cipher, message, pk)
  t.not(cipher, message, 'did not encrypt!')

  t.not(cipher, Buffer.alloc(cipher.length), 'not blank')

  const plain = Buffer.alloc(cipher.length - sodium.crypto_box_SEALBYTES)
  t.absent(sodium.crypto_box_seal_open(plain, cipher, pk2, sk2), 'does not decrypt')
  t.ok(sodium.crypto_box_seal_open(plain, cipher, pk, sk), 'decrypts')
  t.alike(plain, message, 'same message')
})
