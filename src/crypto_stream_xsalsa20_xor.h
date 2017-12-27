#ifndef CRYPTO_STREAM_XSALSA20_XOR_H
#define CRYPTO_STREAM_XSALSA20_XOR_H

#include <sodium.h>

#ifdef __cplusplus
extern "C" {
#endif

// Packing? Alignment?

typedef struct crypto_stream_xsalsa20_xor_state {
    unsigned char nonce[crypto_stream_xsalsa20_NONCEBYTES];
    unsigned char key[crypto_stream_xsalsa20_KEYBYTES];
    unsigned char next_block[64];
    uint8_t remainder;
    uint64_t block_counter;
} crypto_stream_xsalsa20_xor_state;

size_t
crypto_stream_xsalsa20_xor_statebytes(void);

int
crypto_stream_xsalsa20_xor_init(crypto_stream_xsalsa20_xor_state *state,
                                unsigned const char nonce[crypto_stream_xsalsa20_NONCEBYTES],
                                unsigned const char key[crypto_stream_xsalsa20_KEYBYTES]);

int
crypto_stream_xsalsa20_xor_update(crypto_stream_xsalsa20_xor_state *state,
                                  unsigned char *c, const unsigned char *m,
                                  unsigned long long mlen);

int
crypto_stream_xsalsa20_xor_final(crypto_stream_xsalsa20_xor_state *state);

#ifdef __cplusplus
}
#endif


#endif
