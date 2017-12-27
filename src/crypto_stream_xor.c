#include "crypto_stream_xor.h"

#ifdef __cplusplus
extern "C" {
#endif

size_t
crypto_stream_xor_statebytes(void)
{
  return crypto_stream_xsalsa20_xor_statebytes();
}

int
crypto_stream_xor_init(crypto_stream_xor_state *state,
                       unsigned const char nonce[crypto_stream_NONCEBYTES],
                       unsigned const char key[crypto_stream_KEYBYTES])
{
  return crypto_stream_xsalsa20_xor_init(state, nonce, key);
}

int
crypto_stream_xor_update(crypto_stream_xor_state *state,
                         unsigned char *c, const unsigned char *m,
                         unsigned long long mlen)
{
  return crypto_stream_xsalsa20_xor_update(state, c, m, mlen);
}

int
crypto_stream_xor_final(crypto_stream_xor_state *state)
{
  return crypto_stream_xsalsa20_xor_final(state);
}

#ifdef __cplusplus
}
#endif
