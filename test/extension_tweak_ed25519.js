const test = require('brittle')
const sodium = require('..')
const fixtures = require('./fixtures/crypto_tweak_ed25519_sign.js')

test('crypto_tweak', function (t) {
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_keypair(pk, sk)

  const tpk = Buffer.alloc(sodium.extension_tweak_ed25519_BYTES)
  const tsk = Buffer.alloc(sodium.extension_tweak_ed25519_SCALARBYTES)

  const tkpk = Buffer.alloc(sodium.extension_tweak_ed25519_BYTES)
  const tksk = Buffer.alloc(sodium.extension_tweak_ed25519_SCALARBYTES)

  const point = Buffer.alloc(sodium.extension_tweak_ed25519_BYTES)
  const tweak = Buffer.alloc(sodium.extension_tweak_ed25519_SCALARBYTES)

  const ns = Buffer.alloc(32)
  sodium.crypto_generichash(ns, Buffer.from('namespace'))

  t.exception.all(function () {
    sodium.extension_tweak_ed25519_base()
  }, 'should validate input')

  t.exception.all(function () {
    sodium.extension_tweak_ed25519_base(Buffer.alloc(0), Buffer.alloc(0), ns)
  }, 'should validate input length')

  sodium.extension_tweak_ed25519_base(tweak, point, ns)

  const _sk = sk.subarray(0, 32)
  sodium.extension_tweak_ed25519_sk_to_scalar(_sk, sk)

  sodium.extension_tweak_ed25519_pk(tpk, pk, ns)
  sodium.extension_tweak_ed25519_scalar(tsk, _sk, ns)

  sodium.extension_tweak_ed25519_keypair(tkpk, tksk, _sk, ns)

  sodium.extension_tweak_ed25519_pk_add(pk, pk, point)
  sodium.extension_tweak_ed25519_scalar_add(_sk, _sk, tweak)

  t.alike(pk, tpk, 'tweak public key')
  t.alike(_sk, tsk, 'tweak secret key')
  t.alike(pk, tkpk, 'tweak keypair public key')
  t.alike(_sk, tksk, 'tweak keypair secret key')
})

test('extension_tweak_sign', function (t) {
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_keypair(pk, sk)

  const tpk = Buffer.alloc(sodium.extension_tweak_ed25519_BYTES)
  const tsk = Buffer.alloc(sodium.extension_tweak_ed25519_SCALARBYTES)

  const point = Buffer.alloc(sodium.extension_tweak_ed25519_BYTES)
  const tweak = Buffer.alloc(sodium.extension_tweak_ed25519_SCALARBYTES)

  const ns = Buffer.alloc(32)
  sodium.crypto_generichash(ns, Buffer.from('namespace'))

  sodium.extension_tweak_ed25519_base(tweak, point, ns)

  sodium.extension_tweak_ed25519_pk(tpk, pk, ns)
  sodium.extension_tweak_ed25519_sk_to_scalar(tsk, sk)
  sodium.extension_tweak_ed25519_scalar(tsk, tsk, ns)

  sodium.extension_tweak_ed25519_pk_add(pk, pk, point)

  const _sk = sk.subarray(0, 32)
  sodium.extension_tweak_ed25519_sk_to_scalar(_sk, sk)
  sodium.extension_tweak_ed25519_scalar_add(_sk, _sk, tweak)

  const m = Buffer.from('test message')
  const sig = Buffer.alloc(sodium.crypto_sign_BYTES)

  sodium.extension_tweak_ed25519_sign_detached(sig, m, _sk)
  t.ok(sodium.crypto_sign_verify_detached(sig, m, pk))
  t.ok(sodium.crypto_sign_verify_detached(sig, m, tpk))

  sodium.extension_tweak_ed25519_sign_detached(sig, m, tsk)
  t.ok(sodium.crypto_sign_verify_detached(sig, m, pk))
  t.ok(sodium.crypto_sign_verify_detached(sig, m, tpk))
})

test('crypto_tweak sign fixtures', (t) => {
  for (const f of fixtures) {
    const [sk, n, m, sig, tweak, tpk, tn] = f.map(Buffer.from)

    const signature = Buffer.alloc(64)
    const scalar = Buffer.alloc(32)
    const pk = Buffer.alloc(32)

    sodium.extension_tweak_ed25519_sk_to_scalar(scalar, sk)
    t.alike(scalar, n)

    sodium.extension_tweak_ed25519_sign_detached(signature, m, n)
    t.alike(signature, sig)

    sodium.randombytes_buf(signature)
    sodium.crypto_sign_ed25519_sk_to_pk(pk, sk)

    sodium.extension_tweak_ed25519_sign_detached(signature, m, n, pk)
    t.alike(signature, sig)

    sodium.extension_tweak_ed25519_keypair(pk, scalar, n, tweak)
    t.alike(pk, tpk)
    t.alike(scalar, tn)
  }
})
