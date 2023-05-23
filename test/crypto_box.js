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

test('crypto_box_seal/crypto_box_seal_open self-decrypt', function (t) {
  const pubKey = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  const secret = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)

  sodium.crypto_box_keypair(pubKey, secret)

  const msg = Buffer.from('hello world')
  const cipher = Buffer.alloc(sodium.crypto_box_SEALBYTES + msg.length)
  sodium.crypto_box_seal(cipher, msg, pubKey)

  const out = Buffer.alloc(cipher.length - sodium.crypto_box_SEALBYTES)
  sodium.crypto_box_seal_open(out, cipher, pubKey, secret)
  t.alike(out.toString(), msg.toString())
  t.end()
})

test('crypto_box_seal_open cross-decrypt', function (t) {
  const pubKey = Buffer.from(
    'e0bb844ae3f48bb04323c8dfe7c34cf86608db2e2112f927953060c80506287f', 'hex')
  const secret = Buffer.from(
    '036a9de1ecc9d152cf39fed1b3e15bf761ae39a299031adc011cc9809041abfa', 'hex')
  const cipher = Buffer.from(
    '249912e916ad8bcf96a3f9b750da2703' +
    '2eccdf83b5cff0d6a59a8bbe0bcd5823' +
    '5de9fbca55bd5416c754e5e0e0fe2f0c' +
    '4e50df0cb302f1c4378f80', 'hex')

  const out = Buffer.alloc(cipher.length - sodium.crypto_box_SEALBYTES)
  sodium.crypto_box_seal_open(out, cipher, pubKey, secret)
  t.alike(out.toString(), 'hello world')
  t.end()
})

test('crypto_box_seed_keypair', function (t) {
  const seed = Buffer.from([
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5,
    0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
    0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb,
    0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
    0x1d, 0xb9, 0x2c, 0x2a
  ])

  const expPk = Buffer.from([
    0xed, 0x77, 0x49, 0xb4, 0xd9, 0x89, 0xf6, 0x95,
    0x7f, 0x3b, 0xfd, 0xe6, 0xc5, 0x67, 0x67, 0xe9,
    0x88, 0xe2, 0x1c, 0x9f, 0x87, 0x84, 0xd9, 0x1d,
    0x61, 0x00, 0x11, 0xcd, 0x55, 0x3f, 0x9b, 0x06
  ])

  const expSk = Buffer.from([
    0xac, 0xcd, 0x44, 0xeb, 0x8e, 0x93, 0x31, 0x9c,
    0x05, 0x70, 0xbc, 0x11, 0x00, 0x5c, 0x0e, 0x01,
    0x89, 0xd3, 0x4f, 0xf0, 0x2f, 0x6c, 0x17, 0x77,
    0x34, 0x11, 0xad, 0x19, 0x12, 0x93, 0xc9, 0x8f
  ])

  const sk = Buffer.alloc(32)
  const pk = Buffer.alloc(32)

  sodium.crypto_box_seed_keypair(pk, sk, seed)

  t.alike(pk, expPk)
  t.alike(sk, expSk)

  t.end()
})

test('crypto_box_easy', (t) => {
  const alicesk = new Uint8Array([
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72,
    0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
  ])
  const bobpk = new Uint8Array([
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2,
    0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
  ])
  const nonce = new Uint8Array([
    0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
    0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
  ])
  const m = new Uint8Array([
    0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16,
    0xeb, 0xeb, 0x0c, 0x7b, 0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4,
    0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc, 0xe5, 0xec, 0xba, 0xaf,
    0x33, 0xbd, 0x75, 0x1a, 0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29,
    0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4, 0x1d, 0xb6, 0x6c, 0xce,
    0x31, 0x4a, 0xdb, 0x31, 0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d,
    0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57, 0xe2, 0xf6, 0x55, 0x6a,
    0xd6, 0xb1, 0x31, 0x8a, 0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde,
    0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd, 0x49, 0x24, 0xca, 0x1c,
    0x60, 0x90, 0x2e, 0x52, 0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40,
    0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64, 0x5e, 0x07, 0x05
  ])

  const c = new Uint8Array(147)
  sodium.crypto_box_easy(c, m, nonce, bobpk, alicesk)

  const expected1 = new Uint8Array([
    0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5, 0x2a, 0x7d, 0xfb, 0x4b,
    0x3d, 0x33, 0x05, 0xd9, 0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73,
    0xc2, 0x96, 0x50, 0xba, 0x32, 0xfc, 0x76, 0xce, 0x48, 0x33, 0x2e, 0xa7,
    0x16, 0x4d, 0x96, 0xa4, 0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a,
    0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b, 0x4d, 0xa7, 0xf0, 0x11,
    0xec, 0x48, 0xc9, 0x72, 0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2,
    0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5, 0x17, 0x38, 0xb4, 0x8e, 0xee, 0xe3,
    0x14, 0xa7, 0xcc, 0x8a, 0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae,
    0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea, 0xbd, 0x6b, 0xb3, 0x73,
    0x2b, 0xc0, 0xe9, 0xda, 0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde,
    0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3, 0x79, 0x73, 0xf6, 0x22,
    0xa4, 0x3d, 0x14, 0xa6, 0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74,
    0xe3, 0x55, 0xa5
  ])

  t.alike(c, expected1, 'encrypts correctly')

  // This test isn't found upstream, but it seems necessary to have at least
  // one crypto_box_open_easy() working since the next test diverges.
  const o = new Uint8Array(131)
  t.ok(sodium.crypto_box_open_easy(o, expected1, nonce, bobpk, alicesk))
  t.alike(o, m, 'decrypts correctly')

  const guardPage = new Uint8Array(0)

  t.execution(() => sodium.crypto_box_easy(
    c.subarray(0, sodium.crypto_box_MACBYTES),
    guardPage,
    nonce,
    bobpk,
    alicesk
  ))

  const expected2 = new Uint8Array([
    0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23, 0x4e, 0x65, 0x2d, 0x65, 0x1f, 0xa4,
    0xc8, 0xcf, 0xf8, 0x80, 0x8e
  ])

  t.alike(c.subarray(0, expected2.length), expected2)

  t.ok(sodium.crypto_box_open_easy(
    new Uint8Array(0),
    c.subarray(0, sodium.crypto_box_MACBYTES),
    nonce,
    bobpk,
    alicesk
  ))

  c[Math.floor(Math.random() * sodium.crypto_box_MACBYTES)] += 1

  t.absent(sodium.crypto_box_open_easy(new Uint8Array(0), c.subarray(0, sodium.crypto_box_MACBYTES), nonce, bobpk, alicesk))

  t.end()
})

/* eslint-disable */
test('crypto_box2', t => {
  const small_order_p = new Uint8Array([
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
    0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
    0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00
  ])

  const alicepk = new Uint8Array(sodium.crypto_box_PUBLICKEYBYTES)
  const alicesk = new Uint8Array(sodium.crypto_box_SECRETKEYBYTES)
  const bobpk = new Uint8Array(sodium.crypto_box_PUBLICKEYBYTES)
  const bobsk = new Uint8Array(sodium.crypto_box_SECRETKEYBYTES)
  const mac = new Uint8Array(sodium.crypto_box_MACBYTES)
  const nonce = new Uint8Array(sodium.crypto_box_NONCEBYTES)
  const m_size = 7 + Math.floor(Math.random() * 1000)
  const m = new Uint8Array(m_size)
  const m2 = new Uint8Array(m_size)
  const c = new Uint8Array(sodium.crypto_box_MACBYTES + m_size)

  sodium.crypto_box_keypair(alicepk, alicesk)
  sodium.crypto_box_keypair(bobpk, bobsk)

  const mlen = Math.floor(Math.random() * m_size) + 1
  sodium.randombytes_buf(m.subarray(0, mlen))
  sodium.randombytes_buf(nonce.subarray(0, sodium.crypto_box_NONCEBYTES))

  t.execution(() => sodium.crypto_box_easy(c.subarray(0, mlen + sodium.crypto_box_MACBYTES), m.subarray(0, mlen), nonce, bobpk, alicesk))

  t.ok(sodium.crypto_box_open_easy(m2.subarray(0, mlen), c.subarray(0, mlen + sodium.crypto_box_MACBYTES), nonce, alicepk, bobsk))
  t.alike(m.subarray(0, mlen), m2.subarray(0, mlen))

  for (let i = sodium.crypto_box_MACBYTES; i < mlen + sodium.crypto_box_MACBYTES - 1; i++) {
    if (sodium.crypto_box_open_easy(m2.subarray(0, i - sodium.crypto_box_MACBYTES), c.subarray(0, i), nonce, alicepk, bobsk)) {
      t.fail('short open() should fail.')
    }
  }

  c.set(m.subarray(0, mlen))
  t.execution(() => sodium.crypto_box_easy(c.subarray(0, mlen + sodium.crypto_box_MACBYTES), c.subarray(0, mlen), nonce, bobpk, alicesk))

  t.unlike(m.subarray(0, mlen), c.subarray(0, mlen))
  t.unlike(m.subarray(0, mlen), c.subarray(sodium.crypto_box_MACBYTES, sodium.crypto_box_MACBYTES + mlen))

  t.ok(sodium.crypto_box_open_easy(c.subarray(0, mlen), c.subarray(0, mlen + sodium.crypto_box_MACBYTES), nonce, alicepk, bobsk))

  t.end()
})
