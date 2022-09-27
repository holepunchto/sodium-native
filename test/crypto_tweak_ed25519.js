const tape = require('tape')
const sodium = require('../')
const fixtures = require('./fixtures/crypto_tweak_ed25519_sign.js')

tape('crypto_tweak', function (t) {
  var pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  var sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_keypair(pk, sk)

  var tpk = Buffer.alloc(sodium.experimental_crypto_tweak_ed25519_BYTES)
  var tsk = Buffer.alloc(sodium.experimental_crypto_tweak_ed25519_SCALARBYTES)

  var tkpk = Buffer.alloc(sodium.experimental_crypto_tweak_ed25519_BYTES)
  var tksk = Buffer.alloc(sodium.experimental_crypto_tweak_ed25519_SCALARBYTES)

  var point = Buffer.alloc(sodium.experimental_crypto_tweak_ed25519_BYTES)
  var tweak = Buffer.alloc(sodium.experimental_crypto_tweak_ed25519_SCALARBYTES)

  const ns = Buffer.alloc(32)
  sodium.crypto_generichash(ns, Buffer.from('namespace'))

  t.throws(function () {
    sodium.experimental_crypto_tweak_ed25519()
  }, 'should validate input')

  t.throws(function () {
    sodium.experimental_crypto_tweak_ed25519(Buffer.alloc(0), Buffer.alloc(0), ns)
  }, 'should validate input length')

  sodium.experimental_crypto_tweak_ed25519(tweak, point, ns)

  sodium.experimental_crypto_tweak_ed25519_publickey(tpk, pk, ns)
  sodium.experimental_crypto_tweak_ed25519_secretkey(tsk, sk, ns)

  sodium.experimental_crypto_tweak_ed25519_publickey_add(pk, pk, point)

  const _sk = sk.subarray(0, 32)
  sodium.experimental_crypto_tweak_ed25519_sk_to_scalar(_sk, sk)
  sodium.experimental_crypto_tweak_ed25519_keypair(tkpk, tksk, _sk, ns)
  sodium.experimental_crypto_tweak_ed25519_scalar_add(_sk, _sk, tweak)

  t.deepEquals(pk, tpk, 'tweak public key')
  t.deepEquals(_sk, tsk, 'tweak secret key')
  t.deepEquals(pk, tkpk, 'tweak keypair public key')
  t.deepEquals(_sk, tksk, 'tweak keypair secret key')

  t.end()
})

tape('experimental_crypto_tweak_sign', function (t) {
  var pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  var sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_keypair(pk, sk)

  var tpk = Buffer.alloc(sodium.experimental_crypto_tweak_ed25519_BYTES)
  var tsk = Buffer.alloc(sodium.experimental_crypto_tweak_ed25519_SCALARBYTES)

  var point = Buffer.alloc(sodium.experimental_crypto_tweak_ed25519_BYTES)
  var tweak = Buffer.alloc(sodium.experimental_crypto_tweak_ed25519_SCALARBYTES)

  const ns = Buffer.alloc(32)
  sodium.crypto_generichash(ns, Buffer.from('namespace'))

  sodium.experimental_crypto_tweak_ed25519(tweak, point, ns)

  sodium.experimental_crypto_tweak_ed25519_publickey(tpk, pk, ns)
  sodium.experimental_crypto_tweak_ed25519_secretkey(tsk, sk, ns)

  sodium.experimental_crypto_tweak_ed25519_publickey_add(pk, pk, point)

  const _sk = sk.subarray(0, 32)
  sodium.experimental_crypto_tweak_ed25519_sk_to_scalar(_sk, sk)
  sodium.experimental_crypto_tweak_ed25519_scalar_add(_sk, _sk, tweak)

  const m = Buffer.from('test message')
  var sig = Buffer.alloc(sodium.crypto_sign_BYTES)

  sodium.experimental_crypto_tweak_ed25519_sign_detached(sig, m, _sk)
  t.ok(sodium.crypto_sign_verify_detached(sig, m, pk))
  t.ok(sodium.crypto_sign_verify_detached(sig, m, tpk))

  sodium.experimental_crypto_tweak_ed25519_sign_detached(sig, m, tsk)
  t.ok(sodium.crypto_sign_verify_detached(sig, m, pk))
  t.ok(sodium.crypto_sign_verify_detached(sig, m, tpk))

  t.end()
})

tape('crypto_tweak sign fixtures', t => {
  for (const f of fixtures) {
    const [sk, n, m, sig] = f.map(Buffer.from)

    const signature = Buffer.alloc(64)
    const scalar = Buffer.alloc(32)

    sodium.experimental_crypto_tweak_ed25519_sk_to_scalar(scalar, sk)
    t.same(scalar, n)

    sodium.experimental_crypto_tweak_ed25519_sign_detached(signature, m, n)
    t.same(signature, sig)
  }
  t.end()
})
