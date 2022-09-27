#include "tweak.h"

/*
  *EXPERIMENTAL API*

  This module is an experimental implementation of a key tweaking protocol
  over ed25519 keys. The signature algorithm has been reimplemented from
  libsodium, but the nonce generation algorithm is *non-standard*.

  Use at your own risk
*/

void _crypto_tweak_nonce (unsigned char *nonce, const unsigned char *n,
                          const unsigned char *m, unsigned long long mlen)
{
  // dom2(x, y) with x = 0 (not prehashed) and y = "crypto_tweak_ed25519"
  static const unsigned char TWEAK_PREFIX[32 + 2 + 20] = {
      'S', 'i', 'g', 'E', 'd', '2', '5', '5', '1', '9', ' ',
      'n', 'o', ' ', 'E', 'd', '2', '5', '5', '1', '9', ' ',
      'c', 'o', 'l', 'l', 'i', 's', 'i', 'o', 'n', 's', 0,
       20, 'c', 'r', 'y', 'p', 't', 'o', '_', 't', 'w', 'e',
      'a', 'k', '_', 'e', 'd', '2', '5', '5', '1', '9'
  };

  crypto_hash_sha512_state hs;

  crypto_hash_sha512_init(&hs);
  crypto_hash_sha512_update(&hs, TWEAK_PREFIX, sizeof TWEAK_PREFIX);
  crypto_hash_sha512_update(&hs, n, 32);
  crypto_hash_sha512_update(&hs, m, mlen);
  crypto_hash_sha512_final(&hs, nonce);
}

void _crypto_tweak_ed25519(unsigned char *n, unsigned char *q,
                           const unsigned char *ns, unsigned long long nslen)
{
  sodium_memzero(q, sizeof q);

  crypto_hash(n, ns, nslen);
  n[31] &= 127; // clear highest bit

  crypto_scalarmult_ed25519_base_noclamp(q, n);

  // hash tweak until we get a valid tweaked q
  while (crypto_core_ed25519_is_valid_point(q) != 1) {
    crypto_hash(n, n, 32);
    n[31] &= 127; // clear highest bit

    crypto_scalarmult_ed25519_base_noclamp(q, n);
  }
}

void crypto_tweak_ed25519(unsigned char *n, unsigned char *q,
                          const unsigned char *ns, unsigned long long nslen)
{
  unsigned char n64[64];

  crypto_hash(n64, ns, nslen);
  n64[31] &= 127; // clear highest bit

  crypto_scalarmult_ed25519_base_noclamp(q, n64);

  // hash tweak until we get a valid tweaked point
  while (crypto_core_ed25519_is_valid_point(q) != 1) {
    crypto_hash(n64, n64, 32);
    n64[31] &= 127; // clear highest bit

    crypto_scalarmult_ed25519_base_noclamp(q, n64);
  }

  SN_TWEAK_COPY_32(n, n64)
}

void crypto_tweak_ed25519_keypair(unsigned char *pk_out, unsigned char *scalar_out,
                                  unsigned char *scalar, const unsigned char *ns,
                                  unsigned long long nslen)
{
  unsigned char n64[64];

  crypto_hash(n64, ns, nslen);
  n64[31] &= 127; // clear highest bit

  crypto_tweak_ed25519_scalar_add(scalar_out, scalar, n64);
  crypto_scalarmult_ed25519_base_noclamp(pk_out, scalar_out);

  // hash tweak until we get a valid tweaked point
  while (crypto_core_ed25519_is_valid_point(pk_out) != 1) {
    crypto_hash(n64, n64, 32);
    n64[31] &= 127; // clear highest bit

    crypto_tweak_ed25519_scalar_add(scalar_out, scalar, n64);
    crypto_scalarmult_ed25519_base_noclamp(pk_out, scalar_out);
  }
}

int crypto_tweak_ed25519_sign_detached(unsigned char *sig, unsigned long long *siglen_p,
                                       const unsigned char *m, unsigned long long mlen,
                                       const unsigned char *n)
{
  crypto_hash_sha512_state hs;

  unsigned char            pk[32];
  unsigned char            nonce[64];
  unsigned char            R[32];
  unsigned char            hram[64];


  // derive pk from scalar
  if (crypto_scalarmult_ed25519_base_noclamp(pk, n) != 0) {
    return -1;
  }

  _crypto_tweak_nonce(nonce, n, m, mlen);
  crypto_core_ed25519_scalar_reduce(nonce, nonce);

  // R = G ^ nonce : curve point from nonce
  if (crypto_scalarmult_ed25519_base_noclamp(R, nonce) != 0) {
    return -1;
  }

  // generate challenge as h(ram) = hash(R, pk, message)
  crypto_hash_sha512_init(&hs);
  crypto_hash_sha512_update(&hs, R, 32);
  crypto_hash_sha512_update(&hs, pk, 32);
  crypto_hash_sha512_update(&hs, m, mlen);

  crypto_hash_sha512_final(&hs, hram);

  crypto_core_ed25519_scalar_reduce(hram, hram);

  // sig = nonce + n * h(ram)
  crypto_core_ed25519_scalar_mul(sig, hram, n);
  crypto_core_ed25519_scalar_add(sig + 32, nonce, sig);

  SN_TWEAK_COPY_32(sig, R)

  if (siglen_p != NULL) {
    *siglen_p = 64U;
  }

  return 0;
}

// tweak a secret key
void crypto_tweak_ed25519_sk_to_scalar(unsigned char *n, const unsigned char *sk)
{
  unsigned char n64[64];

  // get sk scalar from seed, cf. crypto_sign_keypair_seed
  crypto_hash(n64, sk, 32);
  n64[0] &= 248;
  n64[31] &= 127;
  n64[31] |= 64;

  SN_TWEAK_COPY_32(n, n64)
}

// tweak a secret key
void crypto_tweak_ed25519_secretkey(unsigned char *scalar,
                                    const unsigned char *sk,
                                    const unsigned char *ns,
                                    unsigned long long nslen)
{
  unsigned char _sk[64];
  unsigned char n[64];
  unsigned char q[32];

  // get sk scalar from seed, cf. crypto_sign_keypair_seed
  crypto_hash(_sk, sk, 32);
  _sk[0] &= 248;
  _sk[31] &= 127;
  _sk[31] |= 64;

  _crypto_tweak_ed25519(n, q, ns, nslen);
  crypto_core_ed25519_scalar_add(scalar, n, _sk);
}

// tweak a public key
int crypto_tweak_ed25519_publickey(unsigned char *tpk,
                                    const unsigned char *pk,
                                    const unsigned char *ns,
                                    unsigned long long nslen)
{  
  unsigned char n[64];
  unsigned char q[32];

  _crypto_tweak_ed25519(n, q, ns, nslen);
  return crypto_core_ed25519_add(tpk, q, pk);
}

// add tweak to scalar
void crypto_tweak_ed25519_scalar_add(unsigned char *scalar_out,
                                     const unsigned char *scalar,
                                     const unsigned char *n)
{
  crypto_core_ed25519_scalar_add(scalar_out, scalar, n);
}

// add tweak point to public key
int crypto_tweak_ed25519_publickey_add(unsigned char *tpk,
                                       const unsigned char *pk,
                                       const unsigned char *q)
{
  return crypto_core_ed25519_add(tpk, pk, q);
}
