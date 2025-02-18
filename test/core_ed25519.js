const test = require('brittle')
const sodium = require('..')

const nonCanonicalP = Buffer.from([
  0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
])

const nonCanonicalInvalidP = Buffer.from([
  0xf5, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
])

const maxCanonicalP = Buffer.from([
  0xe4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
])

function addP (S) {
  const P = Buffer.from([
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
  ])

  sodium.sodium_add(S, P)
}

function addL64 (S) {
  const l = Buffer.alloc(sodium.crypto_core_ed25519_NONREDUCEDSCALARBYTES)
  l.set([0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

  sodium.sodium_add(S, l)
}

test('ported libsodium test', function (t) {
  let i

  const h = sodium.sodium_malloc(sodium.crypto_core_ed25519_UNIFORMBYTES)
  // console.log(h, ArrayBuffer.isView(h), Buffer.isBuffer(h), h instanceof ArrayBuffer, h.offset, h.length, h.byteLength)
  // console.log(Buffer.from(h), Buffer.from(h).length)
  const p = sodium.sodium_malloc(sodium.crypto_core_ed25519_BYTES)
  for (i = 0; i < 1000; i++) {
    sodium.randombytes_buf(h.subarray(0, sodium.crypto_core_ed25519_UNIFORMBYTES))
    sodium.crypto_core_ed25519_from_uniform(p, h)
    if (sodium.crypto_core_ed25519_is_valid_point(p) === false) {
      t.fail('crypto_core_ed25519_from_uniform() returned an invalid point')
    }
  }

  const p2 = sodium.sodium_malloc(sodium.crypto_core_ed25519_BYTES)
  const p3 = sodium.sodium_malloc(sodium.crypto_core_ed25519_BYTES)
  sodium.randombytes_buf(h.subarray(0, sodium.crypto_core_ed25519_UNIFORMBYTES))
  sodium.crypto_core_ed25519_from_uniform(p2, h)

  const j = 1 + sodium.randombytes_uniform(100)
  p.copy(p3, 0, 0, sodium.crypto_core_ed25519_BYTES)
  for (i = 0; i < j; i++) {
    sodium.crypto_core_ed25519_add(p, p, p2)
    if (sodium.crypto_core_ed25519_is_valid_point(p) === false) {
      t.fail('crypto_core_add() returned an invalid point\n')
    }
  }

  t.absent(sodium.sodium_memcmp(p.subarray(0, sodium.crypto_core_ed25519_BYTES), p3), 'crypto_core_add() failed')
  for (i = 0; i < j; i++) {
    sodium.crypto_core_ed25519_sub(p, p, p2)
  }
  t.ok(sodium.sodium_memcmp(p.subarray(0, sodium.crypto_core_ed25519_BYTES), p3))
  const sc = sodium.sodium_malloc(sodium.crypto_scalarmult_ed25519_SCALARBYTES)
  sc.fill(0, 0, sodium.crypto_scalarmult_ed25519_SCALARBYTES)
  sc[0] = 8
  p.copy(p2, 0, 0, sodium.crypto_core_ed25519_BYTES)
  p.copy(p3, 0, 0, sodium.crypto_core_ed25519_BYTES)

  for (i = 0; i < 254; i++) {
    sodium.crypto_core_ed25519_add(p2, p2, p2)
  }
  for (i = 0; i < 8; i++) {
    sodium.crypto_core_ed25519_add(p2, p2, p)
  }
  sodium.crypto_scalarmult_ed25519(p3, sc, p)
  t.ok(sodium.sodium_memcmp(p2.subarray(0, sodium.crypto_core_ed25519_BYTES), p3))

  t.ok(sodium.crypto_core_ed25519_is_valid_point(p))

  p.fill(0, 0, sodium.crypto_core_ed25519_BYTES)
  t.absent(sodium.crypto_core_ed25519_is_valid_point(p))

  p[0] = 1
  t.absent(sodium.crypto_core_ed25519_is_valid_point(p))

  p[0] = 2
  t.absent(sodium.crypto_core_ed25519_is_valid_point(p))

  p[0] = 9
  t.ok(sodium.crypto_core_ed25519_is_valid_point(p))

  t.ok(sodium.crypto_core_ed25519_is_valid_point(maxCanonicalP))
  t.absent(sodium.crypto_core_ed25519_is_valid_point(nonCanonicalInvalidP))
  t.absent(sodium.crypto_core_ed25519_is_valid_point(nonCanonicalP))

  p.copy(p2, 0, 0, sodium.crypto_core_ed25519_BYTES)
  addP(p2)
  sodium.crypto_core_ed25519_add(p3, p2, p2)
  sodium.crypto_core_ed25519_sub(p3, p3, p2)
  t.absent(sodium.sodium_memcmp(p2.subarray(0, sodium.crypto_core_ed25519_BYTES), p))
  t.ok(sodium.sodium_memcmp(p3.subarray(0, sodium.crypto_core_ed25519_BYTES), p))

  p[0] = 2
  t.exception.all(() => sodium.crypto_core_ed25519_add(p3, p2, p))
  sodium.crypto_core_ed25519_add(p3, p2, nonCanonicalP)
  t.exception.all(() => sodium.crypto_core_ed25519_add(p3, p2, nonCanonicalInvalidP))
  t.exception.all(() => sodium.crypto_core_ed25519_add(p3, p, p3))
  sodium.crypto_core_ed25519_add(p3, nonCanonicalP, p3)
  t.exception.all(() => sodium.crypto_core_ed25519_add(p3, nonCanonicalInvalidP, p3))

  t.exception.all(() => sodium.crypto_core_ed25519_sub(p3, p2, p))
  sodium.crypto_core_ed25519_sub(p3, p2, nonCanonicalP)
  t.exception.all(() => sodium.crypto_core_ed25519_sub(p3, p2, nonCanonicalInvalidP))
  t.exception.all(() => sodium.crypto_core_ed25519_sub(p3, p, p3))
  sodium.crypto_core_ed25519_sub(p3, nonCanonicalP, p3)
  t.exception.all(() => sodium.crypto_core_ed25519_sub(p3, nonCanonicalInvalidP, p3))

  for (i = 0; i < 1000; i++) {
    sodium.randombytes_buf(h.subarray(0, sodium.crypto_core_ed25519_UNIFORMBYTES))
    sodium.crypto_core_ed25519_from_uniform(p, h)
    sodium.crypto_core_ed25519_scalar_random(sc)
    sodium.crypto_scalarmult_ed25519_noclamp(p2, sc, p)
    if (!sodium.crypto_core_ed25519_is_valid_point(p2)) t.fail()
    sodium.crypto_core_ed25519_scalar_invert(sc, sc)
    sodium.crypto_scalarmult_ed25519_noclamp(p3, sc, p2)
    if (sodium.sodium_memcmp(p3.subarray(0, sodium.crypto_core_ed25519_BYTES), p) === false) t.fail()
  }

  const sc64 = sodium.sodium_malloc(64)
  sodium.crypto_core_ed25519_scalar_random(sc)
  sc.copy(sc64, 0, 0, sodium.crypto_core_ed25519_BYTES)
  sc64.fill(0, sodium.crypto_core_ed25519_BYTES)
  i = sodium.randombytes_uniform(100)
  do {
    addL64(sc64)
  } while (i-- > 0)
  const reduced = sodium.sodium_malloc(sodium.crypto_core_ed25519_SCALARBYTES)
  sodium.crypto_core_ed25519_scalar_reduce(reduced, sc64)
  t.ok(sodium.sodium_memcmp(reduced, sc))

  sodium.randombytes_buf(h.subarray(0, sodium.crypto_core_ed25519_UNIFORMBYTES))
  sodium.crypto_core_ed25519_from_uniform(p, h)
  p.copy(p2, 0, 0, sodium.crypto_core_ed25519_BYTES)
  sodium.crypto_core_ed25519_scalar_random(sc)
  sodium.crypto_scalarmult_ed25519_noclamp(p, sc, p)
  sodium.crypto_core_ed25519_scalar_complement(sc, sc)
  sodium.crypto_scalarmult_ed25519_noclamp(p2, sc, p2)
  sodium.crypto_core_ed25519_add(p3, p, p2)
  sodium.crypto_core_ed25519_from_uniform(p, h)
  sodium.crypto_core_ed25519_sub(p, p, p3)
  if (p[0] !== 0x01) t.fail()
  for (i = 1; i < sodium.crypto_core_ed25519_BYTES; i++) {
    if (p[i] !== 0) t.fail()
  }

  sodium.randombytes_buf(h.subarray(0, sodium.crypto_core_ed25519_UNIFORMBYTES))
  sodium.crypto_core_ed25519_from_uniform(p, h)
  p.copy(p2, 0, 0, sodium.crypto_core_ed25519_BYTES)
  sodium.crypto_core_ed25519_scalar_random(sc)
  sodium.crypto_scalarmult_ed25519_noclamp(p, sc, p)
  sodium.crypto_core_ed25519_scalar_negate(sc, sc)
  sodium.crypto_scalarmult_ed25519_noclamp(p2, sc, p2)
  sodium.crypto_core_ed25519_add(p, p, p2)
  if (p[0] !== 0x01) t.fail()
  for (i = 1; i < sodium.crypto_core_ed25519_BYTES; i++) {
    if (p[i] !== 0) t.fail()
  }

  for (i = 0; i < sodium.crypto_core_ed25519_SCALARBYTES; i++) {
    sc[i] = 255 - i
  }
  sodium.crypto_core_ed25519_scalar_invert(sc, sc)
  t.alike(sc.toString('hex'), '5858cdec40a044b1548b3bb08f8ce0d71103d1f887df84ebc502643dac4df40b', 'inv1')
  sodium.crypto_core_ed25519_scalar_invert(sc, sc)
  t.alike(sc.toString('hex'), '09688ce78a8ff8273f636b0bc748c0cceeeeedecebeae9e8e7e6e5e4e3e2e100', 'inv2')
  for (i = 0; i < sodium.crypto_core_ed25519_SCALARBYTES; i++) {
    sc[i] = 32 - i
  }
  sodium.crypto_core_ed25519_scalar_invert(sc, sc)

  t.alike(sc.toString('hex'), 'f70b4f272b47bd6a1015a511fb3c9fc1b9c21ca4ca2e17d5a225b4c410b9b60d', 'inv3')
  sodium.crypto_core_ed25519_scalar_invert(sc, sc)
  t.alike(sc.toString('hex'), '201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201', 'inv4')

  for (i = 0; i < sodium.crypto_core_ed25519_SCALARBYTES; i++) {
    sc[i] = 255 - i
  }
  sodium.crypto_core_ed25519_scalar_negate(sc, sc)
  t.alike(sc.toString('hex'), 'e46b69758fd3193097398c9717b11e48111112131415161718191a1b1c1d1e0f', 'neg1')
  sodium.crypto_core_ed25519_scalar_negate(sc, sc)
  t.alike(sc.toString('hex'), '09688ce78a8ff8273f636b0bc748c0cceeeeedecebeae9e8e7e6e5e4e3e2e100', 'neg2')
  for (i = 0; i < sodium.crypto_core_ed25519_SCALARBYTES; i++) {
    sc[i] = 32 - i
  }
  sodium.crypto_core_ed25519_scalar_negate(sc, sc)
  t.alike(sc.toString('hex'), 'cdb4d73ffe47f83ebe85e18dcae6cc03f0f0f1f2f3f4f5f6f7f8f9fafbfcfd0e', 'neg3')
  sodium.crypto_core_ed25519_scalar_negate(sc, sc)
  t.alike(sc.toString('hex'), '201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201', 'neg4')

  for (i = 0; i < sodium.crypto_core_ed25519_SCALARBYTES; i++) {
    sc[i] = 255 - i
  }
  sodium.crypto_core_ed25519_scalar_complement(sc, sc)
  t.alike(sc.toString('hex'), 'e56b69758fd3193097398c9717b11e48111112131415161718191a1b1c1d1e0f', 'comp1')
  sodium.crypto_core_ed25519_scalar_complement(sc, sc)
  t.alike(sc.toString('hex'), '09688ce78a8ff8273f636b0bc748c0cceeeeedecebeae9e8e7e6e5e4e3e2e100', 'comp2')
  for (i = 0; i < sodium.crypto_core_ed25519_SCALARBYTES; i++) {
    sc[i] = 32 - i
  }
  sodium.crypto_core_ed25519_scalar_complement(sc, sc)
  t.alike(sc.toString('hex'), 'ceb4d73ffe47f83ebe85e18dcae6cc03f0f0f1f2f3f4f5f6f7f8f9fafbfcfd0e', 'comp3')
  sodium.crypto_core_ed25519_scalar_complement(sc, sc)
  t.alike(sc.toString('hex'), '201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201', 'comp4')

  const sc2 = sodium.sodium_malloc(sodium.crypto_core_ed25519_SCALARBYTES)
  const sc3 = sodium.sodium_malloc(sodium.crypto_core_ed25519_SCALARBYTES)
  for (i = 0; i < 1000; i++) {
    sodium.randombytes_buf(sc.subarray(0, sodium.crypto_core_ed25519_SCALARBYTES))
    sodium.randombytes_buf(sc2.subarray(0, sodium.crypto_core_ed25519_SCALARBYTES))
    sc[sodium.crypto_core_ed25519_SCALARBYTES - 1] &= 0x7f
    sc2[sodium.crypto_core_ed25519_SCALARBYTES - 1] &= 0x7f
    sodium.crypto_core_ed25519_scalar_add(sc3, sc, sc2)
    if (sodium.sodium_is_zero(sc, sodium.crypto_core_ed25519_SCALARBYTES)) t.fail()
    sodium.crypto_core_ed25519_scalar_sub(sc3, sc3, sc2)
    if (sodium.sodium_is_zero(sc, sodium.crypto_core_ed25519_SCALARBYTES)) t.fail()
    sodium.crypto_core_ed25519_scalar_sub(sc3, sc3, sc)
    if (!sodium.sodium_is_zero(sc3, sodium.crypto_core_ed25519_SCALARBYTES)) t.fail()
  }

  sc.fill(0x69, 0, sodium.crypto_core_ed25519_UNIFORMBYTES)
  sc2.fill(0x42, 0, sodium.crypto_core_ed25519_UNIFORMBYTES)
  sodium.crypto_core_ed25519_scalar_add(sc, sc, sc2)
  sodium.crypto_core_ed25519_scalar_add(sc, sc2, sc)
  t.alike(sc.toString('hex'), 'f7567cd87c82ec1c355a6304c143bcc9ecedededededededededededededed0d', 'add1')

  sodium.crypto_core_ed25519_scalar_sub(sc, sc2, sc)
  sodium.crypto_core_ed25519_scalar_sub(sc, sc, sc2)
  t.alike(sc.toString('hex'), 'f67c79849de0253ba142949e1db6224b13121212121212121212121212121202', 'sub1')

  sc.fill(0xcd, 0, sodium.crypto_core_ed25519_UNIFORMBYTES)
  sc2.fill(0x42, 0, sodium.crypto_core_ed25519_UNIFORMBYTES)
  sodium.crypto_core_ed25519_scalar_add(sc, sc, sc2)
  sodium.crypto_core_ed25519_scalar_add(sc, sc2, sc)
  t.alike(sc.toString('hex'), 'b02e8581ce62f69922427c23f970f7e951525252525252525252525252525202', 'add2')

  sodium.crypto_core_ed25519_scalar_sub(sc, sc2, sc)
  sodium.crypto_core_ed25519_scalar_sub(sc, sc, sc2)
  t.alike(sc.toString('hex'), '3da570db4b001cbeb35a7b7fe588e72aaeadadadadadadadadadadadadadad0d', 'sub2')

  // sodium-native: We're hardcoding these in just so we can see if they change
  t.ok(sodium.crypto_core_ed25519_BYTES === 32)
  t.ok(sodium.crypto_core_ed25519_SCALARBYTES === 32)
  t.ok(sodium.crypto_core_ed25519_NONREDUCEDSCALARBYTES === 64)
  t.ok(sodium.crypto_core_ed25519_NONREDUCEDSCALARBYTES >= sodium.crypto_core_ed25519_SCALARBYTES)
  t.ok(sodium.crypto_core_ed25519_UNIFORMBYTES === 32)
  t.ok(sodium.crypto_core_ed25519_UNIFORMBYTES >= sodium.crypto_core_ed25519_BYTES)
})
