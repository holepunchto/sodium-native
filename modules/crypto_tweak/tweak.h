#include <sodium.h>

// copy 32 bytes using int64_t pointers
#define SN_TWEAK_COPY_32(a, b) \
  { \
    long long *dst = (long long *) a; \
    long long *src = (long long *) b; \
    dst[0] = src[0]; \
    dst[1] = src[1]; \
    dst[2] = src[2]; \
    dst[3] = src[3]; \
  }

#define crypto_tweak_ed25519_BYTES crypto_sign_ed25519_PUBLICKEYBYTES

#define crypto_tweak_ed25519_SCALARBYTES crypto_scalarmult_ed25519_SCALARBYTES

int crypto_tweak_ed25519_sign_detached(unsigned char *sig, unsigned long long *siglen_p,
                                       const unsigned char *m, unsigned long long mlen,
                                       const unsigned char *sk);

void crypto_tweak_ed25519(unsigned char *n, unsigned char *q,
                          const unsigned char *ns, unsigned long long nslen);

void crypto_tweak_ed25519_keypair(unsigned char *pk_out, unsigned char *scalar_out,
                                  unsigned char *pk, unsigned char *scalar,
                                  const unsigned char *ns, unsigned long long nslen);

void crypto_tweak_ed25519_sk_to_scalar(unsigned char *n, const unsigned char *sk);

// tweak a secret key
void crypto_tweak_ed25519_secretkey(unsigned char *scalar,
                                    const unsigned char *sk,
                                    const unsigned char *ns,
                                    unsigned long long nslen);

// tweak a public key
int crypto_tweak_ed25519_publickey(unsigned char *tpk,
                                   const unsigned char *pk,
                                   const unsigned char *ns,
                                   unsigned long long nslen);

// add tweak scalar to private key
void crypto_tweak_ed25519_secretkey_add(unsigned char *scalar,
                                        const unsigned char *sk,
                                        const unsigned char *n);

// add tweak point to public key
int crypto_tweak_ed25519_publickey_add(unsigned char *tpk,
                                       const unsigned char *pk,
                                       const unsigned char *q);
