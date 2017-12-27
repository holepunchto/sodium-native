#ifndef CRYPTO_STREAM_XSALSA20_XOR_C
#define CRYPTO_STREAM_XSALSA20_XOR_C

#include <string.h>
#include "crypto_stream_xsalsa20_xor.h"

#ifdef __cplusplus
extern "C" {
#endif

size_t
crypto_stream_xsalsa20_xor_statebytes(void)
{
  return sizeof(crypto_stream_xsalsa20_xor_state);
}

int
crypto_stream_xsalsa20_xor_init(crypto_stream_xsalsa20_xor_state *state,
                                unsigned const char nonce[crypto_stream_xsalsa20_NONCEBYTES],
                                unsigned const char key[crypto_stream_xsalsa20_KEYBYTES])
{
  // If arguments are outright dangerous
  if (0) {
    sodium_misuse();
  }

  state->remainder = 0;
  state->block_counter = 0;
  memcpy(state->nonce, nonce, sizeof(state->nonce));
  memcpy(state->key, key, sizeof(state->key));
  memset(state->next_block, 0, sizeof(state->next_block));

  return 0;
}

int
crypto_stream_xsalsa20_xor_update(crypto_stream_xsalsa20_xor_state *state,
                                  unsigned char *c, const unsigned char *m,
                                  unsigned long long mlen)
{
  // If we have data left over of the next block
  if (state->remainder) {
    uint64_t offset = 0;
    uint8_t rem = state->remainder;

    while (rem < 64 && offset < mlen) {
      c[offset] = state->next_block[rem] ^ 0 ^ m[offset];
      offset++;
      rem++;
    }

    c += offset;
    m += offset;
    mlen -= offset;
    state->remainder = rem % 64; // This should never wrap, but always <= 64

    if (!mlen) return 0;
  }


  state->remainder = mlen & 63;
  mlen -= state->remainder;

  crypto_stream_xsalsa20_xor_ic(c, m, mlen, state->nonce, state->block_counter, state->key);

  state->block_counter += mlen / 64;

  if (state->remainder) {
    sodium_memzero(state->next_block + state->remainder, 64 - state->remainder);
    memcpy(state->next_block, m + mlen, state->remainder);

    crypto_stream_xsalsa20_xor_ic(state->next_block, state->next_block, 64, state->nonce, state->block_counter, state->key);
    memcpy(c + mlen, state->next_block, state->remainder);

    state->block_counter++;
  }

  return 0;
}

int
crypto_stream_xsalsa20_xor_final(crypto_stream_xsalsa20_xor_state *state)
{
  sodium_memzero(state, crypto_stream_xsalsa20_xor_statebytes());

  return 0;
}

#ifdef __cplusplus
}
#endif

#endif
