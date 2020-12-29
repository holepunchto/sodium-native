var test = require('tape')
var sodium = require('..')

test('bad encodings', function (assert) {
  const badEncodingsHex = [
    /* Non-canonical field encodings */
    '00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    '0100000000000000000000000000000000000000000000000000000000000080',

    /* Negative field elements */
    '0100000000000000000000000000000000000000000000000000000000000000',
    '01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20',
    'c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562',
    'c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78',
    '47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24',
    'f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72',
    '87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309',

    /* Non-square x^2 */
    '26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371',
    '4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f',
    'de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b',
    'bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042',
    '2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08',
    'f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22',
    '8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731',
    '2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b',

    /* Negative xy value */
    '3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e',
    'a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220',
    'd483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e',
    '8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32',
    '32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b',
    '227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165',
    '5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e',
    '445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b',

    /* s = -1, which causes y = 0 */
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'
  ]

  badEncodingsHex.forEach(hex => {
    const s = Buffer.from(hex, 'hex', sodium.crypto_core_ristretto255_BYTES)
    assert.notOk(sodium.crypto_core_ristretto255_is_valid_point(s), `${hex} was rejected`)
  })

  assert.end()
})

test('hash to point', function (assert) {
  const hashHex = [
    '5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c1' +
        '4d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6',

    'f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b27' +
        '0102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38',

    '8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c' +
        '27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c',

    'ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2' +
        '150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf',

    '165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec767' +
        '5debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413',

    'a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2' +
        '979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c',

    '2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c7462' +
        '2c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982'
  ]

  hashHex.forEach(hash => {
    const s = sodium.sodium_malloc(sodium.crypto_core_ristretto255_BYTES)
    const u = Buffer.from(hash, 'hex', sodium.crypto_core_ristretto255_HASHBYTES)
    sodium.crypto_core_ristretto255_from_hash(s, u)
    const hex = s.toString('hex')
    assert.ok(hex, `hashed to point ${hex}`)
  })
  assert.end()
})

test('1000 iteration check', function (assert) {
  var l = Buffer.from('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010', 'hex')
  var r = sodium.sodium_malloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  var rInv = sodium.sodium_malloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  var ru = sodium.sodium_malloc(sodium.crypto_core_ristretto255_HASHBYTES)
  var s = sodium.sodium_malloc(sodium.crypto_core_ristretto255_BYTES)
  var s_ = sodium.sodium_malloc(sodium.crypto_core_ristretto255_BYTES)
  var s2 = sodium.sodium_malloc(sodium.crypto_core_ristretto255_BYTES)

  var n = 1000
  for (var i = 0; i < n; i++) {
    sodium.crypto_core_ristretto255_scalar_random(r)
    sodium.crypto_scalarmult_ristretto255_base(s, r)
    assert.ok(sodium.crypto_core_ristretto255_is_valid_point(s), 'sodium.crypto_scalarmult_ristretto255_base() succeeded')

    sodium.crypto_core_ristretto255_random(s)
    assert.ok(sodium.crypto_core_ristretto255_is_valid_point(s), 'sodium.crypto_core_ristretto255_random() succeeded')

    try {
      sodium.crypto_scalarmult_ristretto255(s, l, s)
      assert.notOk(true, 'scalarmult succeeds when multiplying point')
    } catch {
      assert.ok(true, 'scalarmult fails when multiplying point (1)')
    }

    sodium.randombytes_buf(ru)
    sodium.crypto_core_ristretto255_from_hash(s, ru)
    assert.ok(sodium.crypto_core_ristretto255_is_valid_point(s), 'sodium.crypto_core_ristretto255_from_hash() succeeded')

    try {
      sodium.crypto_scalarmult_ristretto255(s2, l, s)
      assert.notOk(true, 'scalarmult succeeds when multiplying point')
    } catch {
      assert.ok(true, 'scalarmult fails when multiplying point (2)')
    }

    sodium.crypto_scalarmult_ristretto255(s2, r, s)
    assert.ok(sodium.crypto_core_ristretto255_is_valid_point(s2), 'sodium.crypto_scalarmult_ristretto255() succeeded')

    try {
      sodium.crypto_core_ristretto255_scalar_invert(rInv, r)
      assert.ok(true, 'sodium.crypto_core_ristretto255_scalar_invert() succeeded')
    } catch {
      assert.notOk(true, 'sodium.crypto_core_ristretto255_scalar_invert() failed')
    }

    sodium.crypto_scalarmult_ristretto255(s_, rInv, s2)
    assert.ok(sodium.crypto_core_ristretto255_is_valid_point(s_), 'sodium.crypto_scalarmult_ristretto255() succeeded')

    assert.ok(s.equals(s_), 'inversion succeeded')

    try {
      sodium.crypto_scalarmult_ristretto255(s2, l, s2)
      assert.notOk(true, 'scalarmult succeeds when multiplying point')
    } catch {
      assert.ok(true, 'scalarmult fails when multiplying point (3)')
    }

    sodium.crypto_core_ristretto255_add(s2, s, s_)
    assert.ok(sodium.crypto_core_ristretto255_is_valid_point(s2), 'addition succeeded')

    sodium.crypto_core_ristretto255_sub(s2, s2, s_)
    assert.ok(sodium.crypto_core_ristretto255_is_valid_point(s2), 'subtraction succeeded')

    assert.ok(s.equals(s2), 's2 + s - s_ == s')
    sodium.crypto_core_ristretto255_sub(s2, s2, s)
    assert.ok(sodium.crypto_core_ristretto255_is_valid_point(s2), 'subtraction succeeded')
  }

  sodium.crypto_core_ristretto255_random(s)
  s_ = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
  s_.fill('fe', 'hex')
  try {
    sodium.crypto_core_ristretto255_add(s2, s_, s)
    assert.ok(true, 'successfully added bad point')
  } catch {
    assert.ok(true, 'failed to add bad point')
  }
  try {
    sodium.crypto_core_ristretto255_add(s2, s, s_)
    assert.ok(true, 'successfully added bad point')
  } catch {
    assert.ok(true, 'failed to add bad point')
  }
  try {
    sodium.crypto_core_ristretto255_add(s2, s_, s_)
    assert.ok(true, 'successfully added bad point')
  } catch {
    assert.ok(true, 'failed to add bad point')
  }
  try {
    sodium.crypto_core_ristretto255_add(s2, s, s)
    assert.ok(true, 'successfully added good points')
  } catch {
    assert.ok(true, 'failed to add good points')
  }
  try {
    sodium.crypto_core_ristretto255_sub(s2, s_, s)
    assert.ok(true, 'successfully added bad point')
  } catch {
    assert.ok(true, 'failed to add bad point')
  }
  try {
    sodium.crypto_core_ristretto255_sub(s2, s, s_)
    assert.ok(true, 'successfully added bad point')
  } catch {
    assert.ok(true, 'failed to add bad point')
  }
  try {
    sodium.crypto_core_ristretto255_sub(s2, s_, s_)
    assert.ok(true, 'successfully added bad point')
  } catch {
    assert.ok(true, 'failed to add bad point')
  }
  try {
    sodium.crypto_core_ristretto255_sub(s2, s, s)
    assert.ok(true, 'successfully added good points')
  } catch {
    assert.ok(true, 'failed to add good points')
  }

  assert.end()
})

test('tv4', function (assert) {
  var r = sodium.sodium_malloc(sodium.crypto_core_ristretto255_NONREDUCEDSCALARBYTES)
  var s1 = sodium.sodium_malloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  var s2 = sodium.sodium_malloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  var s3 = sodium.sodium_malloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  var s4 = sodium.sodium_malloc(sodium.crypto_core_ristretto255_SCALARBYTES)

  sodium.crypto_core_ristretto255_scalar_random(s1)
  sodium.randombytes_buf(r)
  sodium.crypto_core_ristretto255_scalar_reduce(s2, r)
  s1.copy(s4)
  sodium.crypto_core_ristretto255_scalar_add(s3, s1, s2)
  sodium.crypto_core_ristretto255_scalar_sub(s4, s1, s2)
  sodium.crypto_core_ristretto255_scalar_add(s2, s3, s4)
  sodium.crypto_core_ristretto255_scalar_sub(s2, s2, s1)
  sodium.crypto_core_ristretto255_scalar_mul(s2, s3, s2)
  sodium.crypto_core_ristretto255_scalar_invert(s4, s3)
  sodium.crypto_core_ristretto255_scalar_mul(s2, s2, s4)
  sodium.crypto_core_ristretto255_scalar_negate(s1, s1)
  sodium.crypto_core_ristretto255_scalar_add(s2, s2, s1)
  sodium.crypto_core_ristretto255_scalar_complement(s1, s2)
  s1[0]--
  assert.ok(sodium.sodium_is_zero(s1, sodium.crypto_core_ristretto255_SCALARBYTES))
  assert.end()
})

test('main', function (assert) {
  assert.ok(sodium.crypto_core_ristretto255_NONREDUCEDSCALARBYTES >= sodium.crypto_core_ristretto255_SCALARBYTES)
  assert.ok(sodium.crypto_core_ristretto255_HASHBYTES >= sodium.crypto_core_ristretto255_BYTES)
  assert.ok(sodium.crypto_core_ristretto255_BYTES === sodium.crypto_core_ed25519_BYTES)
  assert.ok(sodium.crypto_core_ristretto255_SCALARBYTES === sodium.crypto_core_ed25519_SCALARBYTES)
  assert.ok(sodium.crypto_core_ristretto255_NONREDUCEDSCALARBYTES === sodium.crypto_core_ed25519_NONREDUCEDSCALARBYTES)
  assert.ok(sodium.crypto_core_ristretto255_HASHBYTES >= 2 * sodium.crypto_core_ed25519_UNIFORMBYTES)
  assert.end()
})
