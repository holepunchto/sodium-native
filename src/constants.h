#ifndef SODIDUM_NATIVE_CONSTANTS_H
#define SODIDUM_NATIVE_CONSTANTS_H

#ifndef crypto_generichash_STATEBYTES
#define crypto_generichash_STATEBYTES sizeof(crypto_generichash_state)
#endif

#ifndef crypto_stream_xor_STATEBYTES
#define crypto_stream_xor_STATEBYTES sizeof(crypto_stream_xor_state)
#endif

#ifndef crypto_stream_chacha20_xor_STATEBYTES
#define crypto_stream_chacha20_xor_STATEBYTES sizeof(crypto_stream_chacha20_xor_state)
#endif

#ifndef crypto_onetimeauth_STATEBYTES
#define crypto_onetimeauth_STATEBYTES sizeof(crypto_onetimeauth_state)
#endif

#ifndef crypto_hash_sha256_STATEBYTES
#define crypto_hash_sha256_STATEBYTES sizeof(crypto_hash_sha256_state)
#endif

#ifndef crypto_hash_sha512_STATEBYTES
#define crypto_hash_sha512_STATEBYTES sizeof(crypto_hash_sha512_state)
#endif

// Warning: This is only because we know for now that tags are one byte, and
// it is hard to expose the tag pointer to javascript, other than as a Buffer
#ifndef crypto_secretstream_xchacha20poly1305_TAGBYTES
#define crypto_secretstream_xchacha20poly1305_TAGBYTES 1U
#endif

#ifndef crypto_secretstream_xchacha20poly1305_STATEBYTES
#define crypto_secretstream_xchacha20poly1305_STATEBYTES sizeof(crypto_secretstream_xchacha20poly1305_state)
#endif

#endif
