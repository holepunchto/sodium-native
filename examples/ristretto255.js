var sodium = require('.')

// Perform a secure two-party computation of f(x) = k*p(x).
//
// x is the input sent to the second party by the first party after blinding it using a random invertible scalar r,
// and k is a secret key only known by the second party. p(x) is a hash-to-group function.

// -------- First party -------- Send `a` to second party
var x = Buffer.alloc(sodium.crypto_core_ristretto255_HASHBYTES)
sodium.randombytes_buf(x)

// Compute p = p(x), a group element derived from x
var p = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
sodium.crypto_core_ristretto255_from_hash(p, x)

// Compute a = p + rg
var r = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
var rg = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
var a = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
sodium.crypto_core_ristretto255_scalar_random(r)
sodium.crypto_scalarmult_ristretto255_base(rg, r)
sodium.crypto_core_ristretto255_add(a, p, rg)

// -------- Second party -------- Send v=kg and b=ka to first party
var k = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
sodium.randombytes_buf(k)

// Compute v = kg
var v = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
sodium.crypto_scalarmult_ristretto255_base(v, k)

// Compute b = ka
var b = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
sodium.crypto_scalarmult_ristretto255(b, k, a)

// -------- First party -------- Unblind f(x)
// Compute irv = -rv
var ir = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
var irv = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
sodium.crypto_core_ristretto255_scalar_negate(ir, r)
sodium.crypto_scalarmult_ristretto255(irv, ir, v)

// Compute f(x) = b + (-rv) = k(p + rg) - r(kg)
//              = k(p + g) - kg = kp
var fx = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
sodium.crypto_core_ristretto255_add(fx, b, irv)

console.log('f(x) =', fx)
