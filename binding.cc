#include <assert.h>
#include <bare.h>
#include <js.h>
#include <jstl.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <uv.h>

#include "extensions/pbkdf2/pbkdf2.h"
#include "extensions/tweak/tweak.h"
#include "sodium/crypto_generichash.h"

#define assert_bounds(arraybuffer) \
  assert(arraybuffer##_offset + arraybuffer##_len <= arraybuffer.size())

static inline void
sn_sodium_memzero(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> buf
) {
  sodium_memzero(buf.data(), buf.size_bytes());
}

static inline int
sn_sodium_mlock(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> buf
) {
  return sodium_mlock(buf.data(), buf.size_bytes());
}

static inline int
sn_sodium_munlock(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> buf
) {
  return sodium_munlock(buf.data(), buf.size_bytes());
}

static void
sn_external_arraybuffer_finalize(js_env_t *env, uint8_t *ptr) {
  sodium_free(ptr);
}

static js_arraybuffer_t
sn_sodium_malloc(js_env_t *env, js_receiver_t, uint32_t len) {
  auto ptr = reinterpret_cast<uint8_t *>(sodium_malloc(len));
  assert(ptr != nullptr);

  js_arraybuffer_t buffer;

  int err = js_create_external_arraybuffer<sn_external_arraybuffer_finalize>(env, ptr, len, buffer);
  assert(err == 0);

  return buffer;
}

static void
sn_sodium_free(js_env_t *env, js_receiver_t, js_arraybuffer_t buf) {
  int err;

  std::span<uint8_t> view;
  err = js_get_arraybuffer_info(env, buf, view);
  assert(err == 0);

  if (view.empty()) return;

  err = js_detach_arraybuffer(env, buf);
  assert(err == 0);
}

static inline int
sn_sodium_mprotect_noaccess(js_env_t *env, js_receiver_t, js_arraybuffer_span_t buf) {
  return sodium_mprotect_noaccess(buf.data());
}

static inline int
sn_sodium_mprotect_readonly(js_env_t *env, js_receiver_t, js_arraybuffer_span_t buf) {
  return sodium_mprotect_readonly(buf.data());
}

static inline int
sn_sodium_mprotect_readwrite(js_env_t *env, js_receiver_t, js_arraybuffer_span_t buf) {
  return sodium_mprotect_readwrite(buf.data());
}

static inline uint32_t // TODO: test envless
sn_randombytes_random(js_env_t *env, js_receiver_t) {
  return randombytes_random();
}

static inline uint32_t // TODO: test envless
sn_randombytes_uniform(js_env_t *env, js_receiver_t, uint32_t upper_bound) {
  return randombytes_uniform(upper_bound);
}

static inline void
sn_randombytes_buf(
  js_env_t *env,
  js_receiver_t,
  js_arraybuffer_span_t buf,
  uint32_t buf_offset,
  uint32_t buf_len
) {
  assert_bounds(buf);
  randombytes_buf(&buf[buf_offset], buf_len);
}

static inline void
sn_randombytes_buf_deterministic(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_span_t buf,
  uint32_t buf_offset,
  uint32_t buf_len,

  js_arraybuffer_span_t seed,
  uint32_t seed_offset,
  uint32_t seed_len
) {
  assert_bounds(buf);
  assert_bounds(seed);

  assert(seed_len == randombytes_SEEDBYTES);

  randombytes_buf_deterministic(&buf[buf_offset], buf_len, &seed[seed_offset]);
}

static inline bool
sn_sodium_memcmp(js_env_t *, js_receiver_t, js_typedarray_span_t<> a, js_typedarray_span_t<> b) {
  if (a.size_bytes() != b.size_bytes()) return false;

  return sodium_memcmp(a.data(), b.data(), a.size_bytes()) == 0;
}

static inline void
sn_sodium_increment(js_env_t *, js_receiver_t, js_typedarray_span_t<> n) {
  sodium_increment(n.data(), n.size_bytes());
}

static inline void
sn_sodium_add(js_env_t *, js_receiver_t, js_typedarray_span_t<> a, js_typedarray_span_t<> b) {
  sodium_add(a.data(), b.data(), a.size_bytes());
}

static inline void
sn_sodium_sub(js_env_t *, js_receiver_t, js_typedarray_span_t<> a, js_typedarray_span_t<> b) {
  sodium_sub(a.data(), b.data(), a.size_bytes());
}

static inline int32_t
sn_sodium_compare(js_env_t *, js_receiver_t, js_typedarray_span_t<> a, js_typedarray_span_t<> b) {
  return sodium_compare(a.data(), b.data(), a.size_bytes());
}

static inline bool
sn_sodium_is_zero(js_env_t *, js_receiver_t, js_typedarray_span_t<> buffer, uint32_t len) {
  assert(len <= buffer.size_bytes());

  return sodium_is_zero(buffer.data(), len) != 0;
}

static inline uint32_t
sn_sodium_pad(js_env_t *, js_receiver_t, js_typedarray_span_t<> buf, uint32_t unpadded_buflen, uint32_t blocksize) {
  size_t padded_buflen;

  sodium_pad(&padded_buflen, buf.data(), unpadded_buflen, blocksize, buf.size_bytes());

  return padded_buflen;
}

static inline uint32_t
sn_sodium_unpad(js_env_t *, js_receiver_t, js_typedarray_span_t<> buf, uint32_t padded_buflen, uint32_t blocksize) {
  size_t unpadded_buflen;

  sodium_unpad(&unpadded_buflen, buf.data(), padded_buflen, blocksize);

  return unpadded_buflen;
}

static inline int
sn_crypto_sign_keypair(js_env_t *, js_receiver_t, js_typedarray_span_t<> pk, js_typedarray_span_t<> sk) {
  assert(pk.size_bytes() == crypto_sign_PUBLICKEYBYTES);
  assert(sk.size_bytes() == crypto_sign_SECRETKEYBYTES);

  return crypto_sign_keypair(pk.data(), sk.data());
}

static inline int
sn_crypto_sign_seed_keypair(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> pk,
  js_typedarray_span_t<> sk,
  js_typedarray_span_t<> seed
) {
  assert(pk.size_bytes() == crypto_sign_PUBLICKEYBYTES);
  assert(sk.size_bytes() == crypto_sign_SECRETKEYBYTES);
  assert(seed.size_bytes() == crypto_sign_SEEDBYTES);

  return crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data());
}

static inline int
sn_crypto_sign(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> sm,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> sk
) {
  assert(sm.size_bytes() == crypto_sign_BYTES + m.size_bytes());
  assert(sk.size_bytes() == crypto_sign_SECRETKEYBYTES);

  return crypto_sign(sm.data(), NULL, m.data(), m.size_bytes(), sk.data());
}

static inline bool
sn_crypto_sign_open(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> sm,
  js_typedarray_span_t<> pk
) {
  assert(m.size_bytes() == sm.size_bytes() - crypto_sign_BYTES);
  assert(sm.size_bytes() >= crypto_sign_BYTES);
  assert(pk.size_bytes() == crypto_sign_PUBLICKEYBYTES);

  return crypto_sign_open(m.data(), NULL, sm.data(), sm.size_bytes(), pk.data()) == 0;
}

static inline int
sn_crypto_sign_detached(
  js_env_t *env,
  js_receiver_t,
  js_typedarray_span_t<> sig,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> sk
) {
  assert(sig.size_bytes() == crypto_sign_BYTES);
  assert(sk.size_bytes() == crypto_sign_SECRETKEYBYTES);

  return crypto_sign_detached(sig.data(), NULL, m.data(), m.size_bytes(), sk.data());
}

static inline bool
sn_crypto_sign_verify_detached(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_span_t sig,
  uint32_t sig_offset,
  uint32_t sig_len,

  js_arraybuffer_span_t m,
  uint32_t m_offset,
  uint32_t m_len,

  js_arraybuffer_span_t pk,
  uint32_t pk_offset,
  uint32_t pk_len
) {
  assert_bounds(sig);
  assert_bounds(m);
  assert_bounds(pk);

  assert(sig_len >= crypto_sign_BYTES);
  assert(pk_len == crypto_sign_PUBLICKEYBYTES);

  int res = crypto_sign_verify_detached(&sig[sig_offset], &m[m_offset], m_len, &pk[pk_offset]);
  return res == 0;
}

static inline int
sn_crypto_sign_ed25519_sk_to_pk(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> pk,
  js_typedarray_span_t<> sk
) {
  assert(pk.size_bytes() == crypto_sign_PUBLICKEYBYTES);
  assert(sk.size_bytes() == crypto_sign_SECRETKEYBYTES);

  return crypto_sign_ed25519_sk_to_pk(pk.data(), sk.data());
}

static inline int
sn_crypto_sign_ed25519_pk_to_curve25519(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> x25519_pk,
  js_typedarray_span_t<> ed25519_pk
) {
  assert(x25519_pk.size_bytes() == crypto_box_PUBLICKEYBYTES);
  assert(ed25519_pk.size_bytes() == crypto_sign_PUBLICKEYBYTES);

  return crypto_sign_ed25519_pk_to_curve25519(x25519_pk.data(), ed25519_pk.data());
}

static inline int
sn_crypto_sign_ed25519_sk_to_curve25519(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> x25519_sk,
  js_typedarray_span_t<> ed25519_sk
) {
  assert(x25519_sk.size_bytes() == crypto_box_SECRETKEYBYTES);
  assert(
    ed25519_sk.size_bytes() == crypto_sign_SECRETKEYBYTES ||
    ed25519_sk.size_bytes() == crypto_box_SECRETKEYBYTES
  );

  return crypto_sign_ed25519_sk_to_curve25519(x25519_sk.data(), ed25519_sk.data());
}

static inline int
sn_crypto_generichash(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_span_t out,
  uint32_t out_offset,
  uint32_t out_len,

  js_arraybuffer_span_t in,
  uint32_t in_offset,
  uint32_t in_len,

  js_arraybuffer_span_t key,
  uint32_t key_offset,
  uint32_t key_len
) {
  assert_bounds(out);
  assert(
    out_len >= crypto_generichash_BYTES_MIN &&
    out_len <= crypto_generichash_BYTES_MAX
  );

  assert_bounds(in);

  uint8_t *key_data = NULL;
  if (key_len) {
    assert_bounds(key);
    assert(
      key_len >= crypto_generichash_KEYBYTES_MIN &&
      key_len <= crypto_generichash_KEYBYTES_MAX
    );
    key_data = &key[key_offset];
  }

  return crypto_generichash(&out[out_offset], out_len, &in[in_offset], in_len, key_data, key_len);
}

static inline int
sn_crypto_generichash_batch(
  js_env_t *env,
  js_receiver_t,
  js_typedarray_t<uint8_t> out,
  std::vector<js_typedarray_span_t<>> batch,
  bool use_key,
  js_typedarray_t<uint8_t> key
) {
  int err;

  uint8_t *out_data;
  size_t out_len;
  err = js_get_typedarray_info(env, out, out_data, out_len);
  assert(err == 0);
  assert(
    out_len >= crypto_generichash_BYTES_MIN &&
    out_len <= crypto_generichash_BYTES_MAX
  );

  uint8_t *key_data = NULL;
  size_t key_len = 0;
  if (use_key) {
    int err = js_get_typedarray_info(env, key, key_data, key_len);
    assert(err == 0);
    assert(
      key_len >= crypto_generichash_KEYBYTES_MIN &&
      key_len <= crypto_generichash_KEYBYTES_MAX
    );
  }

  crypto_generichash_state state;
  err = crypto_generichash_init(&state, key_data, key_len, out_len);
  if (err != 0) return err;

  for (auto &buf : batch) {
    err = crypto_generichash_update(&state, buf.data(), buf.size());
    if (err != 0) return err;
  }

  return crypto_generichash_final(&state, out_data, out_len);
}

static inline void
sn_crypto_generichash_keygen(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_span_t key,
  uint32_t key_offset,
  uint32_t key_len
) {
  assert_bounds(key);
  assert(key_len == crypto_generichash_KEYBYTES);

  crypto_generichash_keygen(&key[key_offset]);
}

static inline int
sn_crypto_generichash_init(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_span_t state,
  uint32_t state_offset,
  uint32_t state_len,

  js_arraybuffer_span_t key,
  uint32_t key_offset,
  uint32_t key_len,

  uint32_t out_len
) {
  assert_bounds(state);
  assert(state_len == sizeof(crypto_generichash_state));

  uint8_t *key_data = NULL;
  if (key_len) {
    assert_bounds(key);
    assert(
      key_len >= crypto_generichash_KEYBYTES_MIN &&
      key_len <= crypto_generichash_KEYBYTES_MAX
    );
    key_data = &key[key_offset];
  }

  auto state_data = reinterpret_cast<crypto_generichash_state *>(&state[state_offset]);

  return crypto_generichash_init(state_data, key_data, key_len, out_len);
}

static inline int
sn_crypto_generichash_update(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_span_t state,
  uint32_t state_offset,
  uint32_t state_len,

  js_arraybuffer_span_t in,
  uint32_t in_offset,
  uint32_t in_len
) {
  assert_bounds(state);
  assert_bounds(in);

  assert(state_len == sizeof(crypto_generichash_state));
  auto state_data = reinterpret_cast<crypto_generichash_state *>(&state[state_offset]);

  return crypto_generichash_update(state_data, &in[in_offset], in_len);
}

static inline int
sn_crypto_generichash_final(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_span_t state,
  uint32_t state_offset,
  uint32_t state_len,

  js_arraybuffer_span_t out,
  uint32_t out_offset,
  uint32_t out_len
) {
  assert_bounds(state);
  assert_bounds(out);

  assert(state_len == sizeof(crypto_generichash_state));
  auto state_data = reinterpret_cast<crypto_generichash_state *>(&state[state_offset]);

  return crypto_generichash_final(state_data, &out[out_offset], out_len);
}

static inline int
sn_crypto_box_keypair(js_env_t *, js_receiver_t, js_typedarray_span_t<> pk, js_typedarray_span_t<> sk) {
  assert(pk.size_bytes() == crypto_box_PUBLICKEYBYTES);
  assert(sk.size_bytes() == crypto_box_SECRETKEYBYTES);

  return crypto_box_keypair(pk.data(), sk.data());
}

static inline int
sn_crypto_box_seed_keypair(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> pk,
  js_typedarray_span_t<> sk,
  js_typedarray_span_t<> seed
) {
  assert(pk.size_bytes() == crypto_box_PUBLICKEYBYTES);
  assert(sk.size_bytes() == crypto_box_SECRETKEYBYTES);
  assert(seed.size_bytes() == crypto_box_SEEDBYTES);

  return crypto_box_seed_keypair(pk.data(), sk.data(), seed.data());
}

static inline int
sn_crypto_box_easy(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> pk,
  js_typedarray_span_t<> sk
) {
  assert(c.size_bytes() == m.size_bytes() + crypto_box_MACBYTES);
  assert(n.size_bytes() == crypto_box_NONCEBYTES);
  assert(pk.size_bytes() == crypto_box_PUBLICKEYBYTES);
  assert(sk.size_bytes() == crypto_box_SECRETKEYBYTES);

  return crypto_box_easy(c.data(), m.data(), m.size_bytes(), n.data(), pk.data(), sk.data());
}

static inline bool
sn_crypto_box_open_easy(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> pk,
  js_typedarray_span_t<> sk
) {
  assert(c.size_bytes() >= crypto_box_MACBYTES);
  assert(m.size_bytes() == c.size_bytes() - crypto_box_MACBYTES);
  assert(n.size_bytes() == crypto_box_NONCEBYTES);
  assert(pk.size_bytes() == crypto_box_PUBLICKEYBYTES);
  assert(sk.size_bytes() == crypto_box_SECRETKEYBYTES);

  return crypto_box_open_easy(m.data(), c.data(), c.size_bytes(), n.data(), pk.data(), sk.data()) == 0;
}

static inline int
sn_crypto_box_detached(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> mac,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> pk,
  js_typedarray_span_t<> sk
) {
  assert(c.size_bytes() == m.size_bytes());
  assert(mac.size_bytes() == crypto_box_MACBYTES);
  assert(n.size_bytes() == crypto_box_NONCEBYTES);
  assert(pk.size_bytes() == crypto_box_PUBLICKEYBYTES);
  assert(sk.size_bytes() == crypto_box_SECRETKEYBYTES);

  return crypto_box_detached(c.data(), mac.data(), m.data(), m.size_bytes(), n.data(), pk.data(), sk.data());
}

static inline bool
sn_crypto_box_open_detached(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> mac,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> pk,
  js_typedarray_span_t<> sk
) {
  assert(m.size_bytes() == c.size_bytes());
  assert(mac.size_bytes() == crypto_box_MACBYTES);
  assert(n.size_bytes() == crypto_box_NONCEBYTES);
  assert(pk.size_bytes() == crypto_box_PUBLICKEYBYTES);
  assert(sk.size_bytes() == crypto_box_SECRETKEYBYTES);

  return crypto_box_open_detached(m.data(), c.data(), mac.data(), c.size_bytes(), n.data(), pk.data(), sk.data()) == 0;
}

static inline int
sn_crypto_box_seal(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> pk
) {
  assert(c.size_bytes() == m.size_bytes() + crypto_box_SEALBYTES);
  assert(pk.size_bytes() == crypto_box_PUBLICKEYBYTES);

  return crypto_box_seal(c.data(), m.data(), m.size_bytes(), pk.data());
}

static inline bool
sn_crypto_box_seal_open(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_span_t m,
  uint32_t m_offset,
  uint32_t m_len,

  js_arraybuffer_span_t c,
  uint32_t c_offset,
  uint32_t c_len,

  js_arraybuffer_span_t pk,
  uint32_t pk_offset,
  uint32_t pk_len,

  js_arraybuffer_span_t sk,
  uint32_t sk_offset,
  uint32_t sk_len
) {
  assert_bounds(m);
  assert_bounds(c);
  assert_bounds(pk);
  assert_bounds(sk);

  assert(m_len == c_len - crypto_box_SEALBYTES);
  assert(c_len >= crypto_box_SEALBYTES);
  assert(sk_len == crypto_box_SECRETKEYBYTES);
  assert(pk_len == crypto_box_PUBLICKEYBYTES);

  return crypto_box_seal_open(&m[m_offset], &c[c_offset], c_len, &pk[pk_offset], &sk[sk_offset]) == 0;
}

static inline int
sn_crypto_secretbox_easy(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(c.size_bytes() == m.size_bytes() + crypto_secretbox_MACBYTES);
  assert(n.size_bytes() == crypto_secretbox_NONCEBYTES);
  assert(k.size_bytes() == crypto_secretbox_KEYBYTES);

  return crypto_secretbox_easy(c.data(), m.data(), m.size_bytes(), n.data(), k.data());
}

static inline bool
sn_crypto_secretbox_open_easy(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(m.size_bytes() == c.size_bytes() - crypto_secretbox_MACBYTES);
  assert(c.size_bytes() >= crypto_secretbox_MACBYTES);
  assert(n.size_bytes() == crypto_secretbox_NONCEBYTES);
  assert(k.size_bytes() == crypto_secretbox_KEYBYTES);

  return crypto_secretbox_open_easy(m.data(), c.data(), c.size_bytes(), n.data(), k.data()) == 0;
}

static inline int
sn_crypto_secretbox_detached(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> mac,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(c.size_bytes() == m.size_bytes());
  assert(mac.size_bytes() == crypto_secretbox_MACBYTES);
  assert(n.size_bytes() == crypto_secretbox_NONCEBYTES);
  assert(k.size_bytes() == crypto_secretbox_KEYBYTES);

  return crypto_secretbox_detached(c.data(), mac.data(), m.data(), m.size_bytes(), n.data(), k.data());
}

static inline bool
sn_crypto_secretbox_open_detached(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> mac,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(m.size_bytes() == c.size_bytes());
  assert(mac.size_bytes() == crypto_secretbox_MACBYTES);
  assert(n.size_bytes() == crypto_secretbox_NONCEBYTES);
  assert(k.size_bytes() == crypto_secretbox_KEYBYTES);

  return crypto_secretbox_open_detached(m.data(), c.data(), mac.data(), c.size_bytes(), n.data(), k.data()) == 0;
}

static inline int
sn_crypto_stream(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(n.size_bytes() == crypto_stream_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_KEYBYTES);

  return crypto_stream(c.data(), c.size_bytes(), n.data(), k.data());
}

static inline int
sn_crypto_stream_xor(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_span_t c,
  uint32_t c_offset,
  uint32_t c_len,

  js_arraybuffer_span_t m,
  uint32_t m_offset,
  uint32_t m_len,

  js_arraybuffer_span_t n,
  uint32_t n_offset,
  uint32_t n_len,

  js_arraybuffer_span_t k,
  uint32_t k_offset,
  uint32_t k_len
) {
  assert_bounds(c);
  assert_bounds(m);
  assert_bounds(n);
  assert_bounds(k);

  assert(c_len == m_len);
  assert(n_len == crypto_stream_NONCEBYTES);
  assert(k_len == crypto_stream_KEYBYTES);

  return crypto_stream_xor(&c[c_offset], &m[m_offset], m_len, &n[n_offset], &k[k_offset]);
}

static inline int
sn_crypto_stream_chacha20(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(n.size_bytes() == crypto_stream_chacha20_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_chacha20_KEYBYTES);

  return crypto_stream_chacha20(c.data(), c.size_bytes(), n.data(), k.data());
}

static inline int
sn_crypto_stream_chacha20_xor(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(c.size_bytes() == m.size_bytes());
  assert(n.size_bytes() == crypto_stream_chacha20_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_chacha20_KEYBYTES);

  return crypto_stream_chacha20_xor(c.data(), m.data(), m.size_bytes(), n.data(), k.data());
}

static inline int
sn_crypto_stream_chacha20_xor_ic(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> n,
  uint32_t ic,
  js_typedarray_span_t<> k
) {
  assert(c.size_bytes() == m.size_bytes());
  assert(n.size_bytes() == crypto_stream_chacha20_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_chacha20_KEYBYTES);

  return crypto_stream_chacha20_xor_ic(c.data(), m.data(), m.size_bytes(), n.data(), ic, k.data());
}

static inline int
sn_crypto_stream_chacha20_ietf(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(n.size_bytes() == crypto_stream_chacha20_ietf_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_chacha20_ietf_KEYBYTES);

  return crypto_stream_chacha20_ietf(c.data(), c.size_bytes(), n.data(), k.data());
}

static inline int
sn_crypto_stream_chacha20_ietf_xor(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(c.size_bytes() == m.size_bytes());
  assert(n.size_bytes() == crypto_stream_chacha20_ietf_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_chacha20_ietf_KEYBYTES);

  return crypto_stream_chacha20_ietf_xor(c.data(), m.data(), m.size_bytes(), n.data(), k.data());
}

static inline int
sn_crypto_stream_chacha20_ietf_xor_ic(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> n,
  uint32_t ic,
  js_typedarray_span_t<> k
) {
  assert(c.size_bytes() == m.size_bytes());
  assert(n.size_bytes() == crypto_stream_chacha20_ietf_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_chacha20_ietf_KEYBYTES);

  return crypto_stream_chacha20_ietf_xor_ic(c.data(), m.data(), m.size_bytes(), n.data(), ic, k.data());
}

static inline int
sn_crypto_stream_xchacha20(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(n.size_bytes() == crypto_stream_xchacha20_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_xchacha20_KEYBYTES);

  return crypto_stream_xchacha20(c.data(), c.size_bytes(), n.data(), k.data());
}

static inline int
sn_crypto_stream_xchacha20_xor(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(c.size_bytes() == m.size_bytes());
  assert(n.size_bytes() == crypto_stream_xchacha20_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_xchacha20_KEYBYTES);

  return crypto_stream_xchacha20_xor(c.data(), m.data(), m.size_bytes(), n.data(), k.data());
}

static inline int
sn_crypto_stream_xchacha20_xor_ic(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> n,
  uint32_t ic,
  js_typedarray_span_t<> k
) {
  assert(c.size_bytes() == m.size_bytes());
  assert(n.size_bytes() == crypto_stream_xchacha20_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_xchacha20_KEYBYTES);

  return crypto_stream_xchacha20_xor_ic(c.data(), m.data(), m.size_bytes(), n.data(), ic, k.data());
}

static inline int
sn_crypto_stream_salsa20(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(n.size_bytes() == crypto_stream_salsa20_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_salsa20_KEYBYTES);

  return crypto_stream_salsa20(c.data(), c.size_bytes(), n.data(), k.data());
}

static inline int
sn_crypto_stream_salsa20_xor(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(c.size_bytes() == m.size_bytes());
  assert(n.size_bytes() == crypto_stream_salsa20_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_salsa20_KEYBYTES);

  return crypto_stream_salsa20_xor(c.data(), m.data(), m.size_bytes(), n.data(), k.data());
}

static inline int
sn_crypto_stream_salsa20_xor_ic(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> n,
  uint32_t ic,
  js_typedarray_span_t<> k
) {
  assert(c.size_bytes() == m.size_bytes());
  assert(n.size_bytes() == crypto_stream_salsa20_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_salsa20_KEYBYTES);

  return crypto_stream_salsa20_xor_ic(c.data(), m.data(), m.size_bytes(), n.data(), ic, k.data());
}

static inline int
sn_crypto_auth(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> out,
  js_typedarray_span_t<> in,
  js_typedarray_span_t<> k
) {
  assert(out.size_bytes() == crypto_auth_BYTES);
  assert(k.size_bytes() == crypto_auth_KEYBYTES);

  return crypto_auth(out.data(), in.data(), in.size_bytes(), k.data());
}

static inline bool
sn_crypto_auth_verify(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> h,
  js_typedarray_span_t<> in,
  js_typedarray_span_t<> k
) {
  assert(h.size_bytes() == crypto_auth_BYTES);
  assert(k.size_bytes() == crypto_auth_KEYBYTES);

  return crypto_auth_verify(h.data(), in.data(), in.size_bytes(), k.data()) == 0;
}

static inline int
sn_crypto_onetimeauth(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> out,
  js_typedarray_span_t<> in,
  js_typedarray_span_t<> k
) {
  assert(out.size_bytes() == crypto_onetimeauth_BYTES);
  assert(k.size_bytes() == crypto_onetimeauth_KEYBYTES);

  return crypto_onetimeauth(out.data(), in.data(), in.size_bytes(), k.data());
}

static inline int
sn_crypto_onetimeauth_init(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<crypto_onetimeauth_state, 1> state,
  js_typedarray_span_t<> k
) {
  assert(k.size_bytes() == crypto_onetimeauth_KEYBYTES);
  return crypto_onetimeauth_init(&*state, k.data());
}

static inline int
sn_crypto_onetimeauth_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<crypto_onetimeauth_state, 1> state,
  js_typedarray_span_t<> in
) {
  return crypto_onetimeauth_update(&*state, in.data(), in.size_bytes());
}

static inline int
sn_crypto_onetimeauth_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<crypto_onetimeauth_state, 1> state,
  js_typedarray_span_t<> out
) {
  assert(out.size_bytes() == crypto_onetimeauth_BYTES);

  return crypto_onetimeauth_final(&*state, out.data());
}

static inline bool
sn_crypto_onetimeauth_verify(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> h,
  js_typedarray_span_t<> in,
  js_typedarray_span_t<> k
) {
  assert(h.size_bytes() == crypto_onetimeauth_BYTES);
  assert(k.size_bytes() == crypto_onetimeauth_KEYBYTES);

  return crypto_onetimeauth_verify(h.data(), in.data(), in.size_bytes(), k.data()) == 0;
}

// CHECK: memlimit can be >32bit
static inline int
sn_crypto_pwhash(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> out,
  js_typedarray_span_of_t<char> passwd,
  js_typedarray_span_t<> salt,
  uint64_t opslimit,
  uint64_t memlimit,
  int32_t alg
) {
  assert(out.size_bytes() >= crypto_pwhash_BYTES_MIN);
  assert(out.size_bytes() <= crypto_pwhash_BYTES_MAX);
  assert(salt.size_bytes() == crypto_pwhash_SALTBYTES);
  assert(opslimit >= crypto_pwhash_OPSLIMIT_MIN);
  assert(opslimit <= crypto_pwhash_OPSLIMIT_MAX);
  assert(memlimit >= crypto_pwhash_MEMLIMIT_MIN);
  assert(memlimit <= crypto_pwhash_MEMLIMIT_MAX);
  assert(alg == 1 || alg == 2); // Argon2i or Argon2id

  return crypto_pwhash(
    out.data(),
    out.size_bytes(),
    passwd.data(),
    passwd.size_bytes(),
    salt.data(),
    opslimit,
    memlimit,
    alg
  );
}

static inline int
sn_crypto_pwhash_str(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<char> out,
  js_typedarray_span_of_t<char> passwd,
  uint64_t opslimit,
  uint64_t memlimit
) {
  assert(out.size_bytes() == crypto_pwhash_STRBYTES);
  assert(opslimit >= crypto_pwhash_OPSLIMIT_MIN);
  assert(opslimit <= crypto_pwhash_OPSLIMIT_MAX);
  assert(memlimit >= crypto_pwhash_MEMLIMIT_MIN);
  assert(memlimit <= crypto_pwhash_MEMLIMIT_MAX);

  return crypto_pwhash_str(
    out.data(),
    passwd.data(),
    passwd.size_bytes(),
    opslimit,
    memlimit
  );
}

static inline bool
sn_crypto_pwhash_str_verify(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<char> str,
  js_typedarray_span_of_t<char> passwd
) {
  assert(str.size_bytes() == crypto_pwhash_STRBYTES);

  int res = crypto_pwhash_str_verify(
    str.data(),
    passwd.data(),
    passwd.size_bytes()
  );

  return res == 0;
}

// CHECK: returns 1, 0, -1
static inline bool
sn_crypto_pwhash_str_needs_rehash(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<char> str,
  uint64_t opslimit,
  uint64_t memlimit
) {
  assert(str.size_bytes() == crypto_pwhash_STRBYTES);
  assert(opslimit >= crypto_pwhash_OPSLIMIT_MIN);
  assert(opslimit <= crypto_pwhash_OPSLIMIT_MAX);
  assert(memlimit >= crypto_pwhash_MEMLIMIT_MIN);
  assert(memlimit <= crypto_pwhash_MEMLIMIT_MAX);

  int res = crypto_pwhash_str_needs_rehash(
    str.data(),
    opslimit,
    memlimit
  );

  return res != 0;
}

// CHECK: memlimit can be >32bit
static inline int
sn_crypto_pwhash_scryptsalsa208sha256(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> out,
  js_typedarray_span_of_t<char> passwd,
  js_typedarray_span_t<> salt,
  uint64_t opslimit,
  uint64_t memlimit
) {
  assert(out.size_bytes() >= crypto_pwhash_scryptsalsa208sha256_BYTES_MIN);
  assert(out.size_bytes() <= crypto_pwhash_scryptsalsa208sha256_BYTES_MAX);
  assert(salt.size_bytes() == crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
  assert(opslimit >= crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN);
  assert(opslimit <= crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX);
  assert(memlimit >= crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN);
  assert(memlimit <= crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX);

  return crypto_pwhash_scryptsalsa208sha256(
    out.data(),
    out.size_bytes(),
    passwd.data(),
    passwd.size_bytes(),
    salt.data(),
    opslimit,
    memlimit
  );
}

static inline int
sn_crypto_pwhash_scryptsalsa208sha256_str(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<char> out,
  js_typedarray_span_of_t<char> passwd,
  uint64_t opslimit,
  uint64_t memlimit
) {
  assert(out.size_bytes() == crypto_pwhash_scryptsalsa208sha256_STRBYTES);
  assert(opslimit >= crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN);
  assert(opslimit <= crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX);
  assert(memlimit >= crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN);
  assert(memlimit <= crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX);

  return crypto_pwhash_scryptsalsa208sha256_str(
    out.data(),
    passwd.data(),
    passwd.size_bytes(),
    opslimit,
    memlimit
  );
}

static inline bool
sn_crypto_pwhash_scryptsalsa208sha256_str_verify(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<char> str,
  js_typedarray_span_of_t<char> passwd
) {
  assert(str.size_bytes() == crypto_pwhash_scryptsalsa208sha256_STRBYTES);

  int res = crypto_pwhash_scryptsalsa208sha256_str_verify(
    str.data(),
    passwd.data(),
    passwd.size_bytes()
  );

  return res == 0;
}

static inline bool
sn_crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<char> str,
  uint64_t opslimit,
  uint64_t memlimit
) {
  assert(str.size_bytes() == crypto_pwhash_scryptsalsa208sha256_STRBYTES);
  assert(opslimit >= crypto_pwhash_OPSLIMIT_MIN);
  assert(opslimit <= crypto_pwhash_OPSLIMIT_MAX);
  assert(memlimit >= crypto_pwhash_MEMLIMIT_MIN);
  assert(memlimit <= crypto_pwhash_MEMLIMIT_MAX);

  int res = crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(
    str.data(),
    opslimit,
    memlimit
  );

  return res != 0;
}

static inline int
sn_crypto_kx_keypair(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> pk,
  js_typedarray_span_t<> sk
) {
  assert(pk.size_bytes() == crypto_kx_PUBLICKEYBYTES);
  assert(sk.size_bytes() == crypto_kx_SECRETKEYBYTES);

  return crypto_kx_keypair(pk.data(), sk.data());
}

static inline int
sn_crypto_kx_seed_keypair(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> pk,
  js_typedarray_span_t<> sk,
  js_typedarray_span_t<> seed
) {
  assert(pk.size_bytes() == crypto_kx_PUBLICKEYBYTES);
  assert(sk.size_bytes() == crypto_kx_SECRETKEYBYTES);
  assert(seed.size_bytes() == crypto_kx_SEEDBYTES);

  return crypto_kx_seed_keypair(pk.data(), sk.data(), seed.data());
}

static inline int
sn_crypto_kx_client_session_keys(
  js_env_t *,
  js_receiver_t,
  std::optional<js_typedarray_span_t<>> rx,
  std::optional<js_typedarray_span_t<>> tx,
  js_typedarray_span_t<> client_pk,
  js_typedarray_span_t<> client_sk,
  js_typedarray_span_t<> server_pk
) {
  assert(rx.has_value() || tx.has_value());

  if (rx) assert(rx->size_bytes() == crypto_kx_SESSIONKEYBYTES);
  if (tx) assert(tx->size_bytes() == crypto_kx_SESSIONKEYBYTES);

  assert(client_pk.size_bytes() == crypto_kx_PUBLICKEYBYTES);
  assert(client_sk.size_bytes() == crypto_kx_SECRETKEYBYTES);
  assert(server_pk.size_bytes() == crypto_kx_PUBLICKEYBYTES);

  return crypto_kx_client_session_keys(
    rx ? rx->data() : nullptr,
    tx ? tx->data() : nullptr,
    client_pk.data(),
    client_sk.data(),
    server_pk.data()
  );
}

static inline int
sn_crypto_kx_server_session_keys(
  js_env_t *,
  js_receiver_t,
  std::optional<js_typedarray_span_t<>> rx,
  std::optional<js_typedarray_span_t<>> tx,
  js_typedarray_span_t<> server_pk,
  js_typedarray_span_t<> server_sk,
  js_typedarray_span_t<> client_pk
) {
  assert(rx.has_value() || tx.has_value());

  if (rx) assert(rx->size_bytes() == crypto_kx_SESSIONKEYBYTES);
  if (tx) assert(tx->size_bytes() == crypto_kx_SESSIONKEYBYTES);

  assert(server_pk.size_bytes() == crypto_kx_PUBLICKEYBYTES);
  assert(server_sk.size_bytes() == crypto_kx_SECRETKEYBYTES);
  assert(client_pk.size_bytes() == crypto_kx_PUBLICKEYBYTES);

  return crypto_kx_server_session_keys(
    rx ? rx->data() : nullptr,
    tx ? tx->data() : nullptr,
    server_pk.data(),
    server_sk.data(),
    client_pk.data()
  );
}

static inline int
sn_crypto_scalarmult_base(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> q,
  js_typedarray_span_t<> n
) {
  assert(q.size_bytes() == crypto_scalarmult_BYTES);
  assert(n.size_bytes() == crypto_scalarmult_SCALARBYTES);

  return crypto_scalarmult_base(q.data(), n.data());
}

static inline int
sn_crypto_scalarmult(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> q,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> p
) {
  assert(q.size_bytes() == crypto_scalarmult_BYTES);
  assert(n.size_bytes() == crypto_scalarmult_SCALARBYTES);
  assert(p.size_bytes() == crypto_scalarmult_BYTES);

  return crypto_scalarmult(q.data(), n.data(), p.data());
}

static inline int
sn_crypto_scalarmult_ed25519_base(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> q,
  js_typedarray_span_t<> n
) {
  assert(q.size_bytes() == crypto_scalarmult_ed25519_BYTES);
  assert(n.size_bytes() == crypto_scalarmult_ed25519_SCALARBYTES);

  return crypto_scalarmult_ed25519_base(q.data(), n.data());
}

static inline int
sn_crypto_scalarmult_ed25519(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> q,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> p
) {
  assert(q.size_bytes() == crypto_scalarmult_ed25519_BYTES);
  assert(n.size_bytes() == crypto_scalarmult_ed25519_SCALARBYTES);
  assert(p.size_bytes() == crypto_scalarmult_ed25519_BYTES);

  return crypto_scalarmult_ed25519(q.data(), n.data(), p.data());
}

static inline bool
sn_crypto_core_ed25519_is_valid_point(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> p
) {
  assert(p.size_bytes() == crypto_core_ed25519_BYTES);

  return crypto_core_ed25519_is_valid_point(p.data()) != 0;
}

static inline int
sn_crypto_core_ed25519_from_uniform(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> p,
  js_typedarray_span_t<> r
) {
  assert(p.size_bytes() == crypto_core_ed25519_BYTES);
  assert(r.size_bytes() == crypto_core_ed25519_UNIFORMBYTES);

  return crypto_core_ed25519_from_uniform(p.data(), r.data());
}

static inline int
sn_crypto_scalarmult_ed25519_base_noclamp(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> q,
  js_typedarray_span_t<> n
) {
  assert(q.size_bytes() == crypto_scalarmult_ed25519_BYTES);
  assert(n.size_bytes() == crypto_scalarmult_ed25519_SCALARBYTES);

  return crypto_scalarmult_ed25519_base_noclamp(q.data(), n.data());
}

static inline int
sn_crypto_scalarmult_ed25519_noclamp(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> q,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> p
) {
  assert(q.size_bytes() == crypto_scalarmult_ed25519_BYTES);
  assert(n.size_bytes() == crypto_scalarmult_ed25519_SCALARBYTES);
  assert(p.size_bytes() == crypto_scalarmult_ed25519_BYTES);

  return crypto_scalarmult_ed25519_noclamp(q.data(), n.data(), p.data());
}

static inline int
sn_crypto_core_ed25519_add(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> r,
  js_typedarray_span_t<> p,
  js_typedarray_span_t<> q
) {
  assert(r.size_bytes() == crypto_core_ed25519_BYTES);
  assert(p.size_bytes() == crypto_core_ed25519_BYTES);
  assert(q.size_bytes() == crypto_core_ed25519_BYTES);

  return crypto_core_ed25519_add(r.data(), p.data(), q.data());
}

static inline int
sn_crypto_core_ed25519_sub(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> r,
  js_typedarray_span_t<> p,
  js_typedarray_span_t<> q
) {
  assert(r.size_bytes() == crypto_core_ed25519_BYTES);
  assert(p.size_bytes() == crypto_core_ed25519_BYTES);
  assert(q.size_bytes() == crypto_core_ed25519_BYTES);

  return crypto_core_ed25519_sub(r.data(), p.data(), q.data());
}

static inline void
sn_crypto_core_ed25519_scalar_random(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> r
) {
  assert(r.size_bytes() == crypto_core_ed25519_SCALARBYTES);

  crypto_core_ed25519_scalar_random(r.data());
}

static inline void
sn_crypto_core_ed25519_scalar_reduce(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> r,
  js_typedarray_span_t<> s
) {
  assert(r.size_bytes() == crypto_core_ed25519_SCALARBYTES);
  assert(s.size_bytes() == crypto_core_ed25519_NONREDUCEDSCALARBYTES);

  crypto_core_ed25519_scalar_reduce(r.data(), s.data());
}

static inline void
sn_crypto_core_ed25519_scalar_invert(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> recip,
  js_typedarray_span_t<> s
) {
  assert(recip.size_bytes() == crypto_core_ed25519_SCALARBYTES);
  assert(s.size_bytes() == crypto_core_ed25519_SCALARBYTES);

  crypto_core_ed25519_scalar_invert(recip.data(), s.data());
}

static inline void
sn_crypto_core_ed25519_scalar_negate(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> neg,
  js_typedarray_span_t<> s
) {
  assert(neg.size_bytes() == crypto_core_ed25519_SCALARBYTES);
  assert(s.size_bytes() == crypto_core_ed25519_SCALARBYTES);

  crypto_core_ed25519_scalar_negate(neg.data(), s.data());
}

static inline void
sn_crypto_core_ed25519_scalar_complement(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> comp,
  js_typedarray_span_t<> s
) {
  assert(comp.size_bytes() == crypto_core_ed25519_SCALARBYTES);
  assert(s.size_bytes() == crypto_core_ed25519_SCALARBYTES);

  crypto_core_ed25519_scalar_complement(comp.data(), s.data());
}

static inline void
sn_crypto_core_ed25519_scalar_add(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> z,
  js_typedarray_span_t<> x,
  js_typedarray_span_t<> y
) {
  assert(z.size_bytes() == crypto_core_ed25519_SCALARBYTES);
  assert(x.size_bytes() == crypto_core_ed25519_SCALARBYTES);
  assert(y.size_bytes() == crypto_core_ed25519_SCALARBYTES);

  crypto_core_ed25519_scalar_add(z.data(), x.data(), y.data());
}

static inline void
sn_crypto_core_ed25519_scalar_sub(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> z,
  js_typedarray_span_t<> x,
  js_typedarray_span_t<> y
) {
  assert(z.size_bytes() == crypto_core_ed25519_SCALARBYTES);
  assert(x.size_bytes() == crypto_core_ed25519_SCALARBYTES);
  assert(y.size_bytes() == crypto_core_ed25519_SCALARBYTES);

  crypto_core_ed25519_scalar_sub(z.data(), x.data(), y.data());
}

static inline int
sn_crypto_shorthash(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> out,
  js_typedarray_span_t<> in,
  js_typedarray_span_t<> k
) {
  assert(out.size_bytes() == crypto_shorthash_BYTES);
  assert(k.size_bytes() == crypto_shorthash_KEYBYTES);

  return crypto_shorthash(out.data(), in.data(), in.size_bytes(), k.data());
}

static inline void
sn_crypto_kdf_keygen(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> key
) {
  assert(key.size_bytes() == crypto_kdf_KEYBYTES);

  crypto_kdf_keygen(key.data());
}

static inline int
sn_crypto_kdf_derive_from_key(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> subkey,
  uint64_t subkey_id,
  js_typedarray_span_of_t<char> ctx,
  js_typedarray_span_t<> key
) {
  assert(subkey.size_bytes() >= crypto_kdf_BYTES_MIN);
  assert(subkey.size_bytes() <= crypto_kdf_BYTES_MAX);
  assert(ctx.size_bytes() == crypto_kdf_CONTEXTBYTES);
  assert(key.size_bytes() == crypto_kdf_KEYBYTES);

  return crypto_kdf_derive_from_key(
    subkey.data(),
    subkey.size_bytes(),
    subkey_id,
    ctx.data(),
    key.data()
  );
}

static inline int
sn_crypto_hash(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> out,
  js_typedarray_span_t<> in
) {
  assert(out.size_bytes() == crypto_hash_BYTES);

  return crypto_hash(out.data(), in.data(), in.size_bytes());
}

static inline int
sn_crypto_hash_sha256(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> out,
  js_typedarray_span_t<> in
) {
  assert(out.size_bytes() == crypto_hash_sha256_BYTES);

  return crypto_hash_sha256(out.data(), in.data(), in.size_bytes());
}

static inline int
sn_crypto_hash_sha256_init(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<crypto_hash_sha256_state, 1> state
) {
  return crypto_hash_sha256_init(&*state);
}

static inline int
sn_crypto_hash_sha256_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<crypto_hash_sha256_state, 1> state,
  js_typedarray_span_t<> in
) {
  return crypto_hash_sha256_update(&*state, in.data(), in.size_bytes());
}

static inline int
sn_crypto_hash_sha256_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<crypto_hash_sha256_state, 1> state,
  js_typedarray_span_t<> out
) {
  assert(out.size_bytes() == crypto_hash_sha256_BYTES);

  return crypto_hash_sha256_final(&*state, out.data());
}

static inline int
sn_crypto_hash_sha512(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> out,
  js_typedarray_span_t<> in
) {
  assert(out.size_bytes() == crypto_hash_sha512_BYTES);

  return crypto_hash_sha512(out.data(), in.data(), in.size_bytes());
}

static inline int
sn_crypto_hash_sha512_init(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<crypto_hash_sha512_state, 1> state
) {
  return crypto_hash_sha512_init(&*state);
}

static inline int
sn_crypto_hash_sha512_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<crypto_hash_sha512_state, 1> state,
  js_typedarray_span_t<> in
) {
  return crypto_hash_sha512_update(&*state, in.data(), in.size_bytes());
}

static inline int
sn_crypto_hash_sha512_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<crypto_hash_sha512_state, 1> state,
  js_typedarray_span_t<> out
) {
  assert(out.size_bytes() == crypto_hash_sha512_BYTES);

  return crypto_hash_sha512_final(&*state, out.data());
}

static inline void
sn_crypto_aead_xchacha20poly1305_ietf_keygen(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> k
) {
  assert(k.size_bytes() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

  crypto_aead_xchacha20poly1305_ietf_keygen(k.data());
}

static inline uint64_t
sn_crypto_aead_xchacha20poly1305_ietf_encrypt(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m,
  std::optional<js_typedarray_span_t<>> ad,
  js_typedarray_span_t<> npub,
  js_typedarray_span_t<> k
) {
  assert(c.size_bytes() == m.size_bytes() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
  assert(c.size_bytes() <= 0xffffffff);
  assert(npub.size_bytes() == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  assert(k.size_bytes() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

  uint8_t *ad_data = nullptr;
  size_t ad_size = 0;
  if (ad) {
    ad_data = ad->data();
    ad_size = ad->size_bytes();
  }

  unsigned long long clen = 0;
  int status = crypto_aead_xchacha20poly1305_ietf_encrypt(
    c.data(),
    &clen,
    m.data(),
    m.size_bytes(),
    ad_data,
    ad_size,
    nullptr,
    npub.data(),
    k.data()
  );

  if (status < 0) return status;

  return clen;
}

static inline uint64_t
sn_crypto_aead_xchacha20poly1305_ietf_decrypt(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> c,
  std::optional<js_typedarray_span_t<>> ad,
  js_typedarray_span_t<> npub,
  js_typedarray_span_t<> k
) {
  assert(m.size_bytes() == c.size_bytes() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
  assert(m.size_bytes() <= 0xffffffff);
  assert(npub.size_bytes() == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  assert(k.size_bytes() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

  uint8_t *ad_data = nullptr;
  size_t ad_size = 0;
  if (ad) {
    ad_data = ad->data();
    ad_size = ad->size_bytes();
  }

  unsigned long long mlen = 0;
  int status = crypto_aead_xchacha20poly1305_ietf_decrypt(
    m.data(),
    &mlen,
    nullptr,
    c.data(),
    c.size_bytes(),
    ad_data,
    ad_size,
    npub.data(),
    k.data()
  );

  if (status < 0) return status;

  return mlen;
}

static inline uint64_t
sn_crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> mac,
  js_typedarray_span_t<> m,
  std::optional<js_typedarray_span_t<>> ad,
  js_typedarray_span_t<> npub,
  js_typedarray_span_t<> k
) {
  assert(c.size_bytes() == m.size_bytes());
  assert(mac.size_bytes() == crypto_aead_xchacha20poly1305_ietf_ABYTES);
  assert(npub.size_bytes() == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  assert(k.size_bytes() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

  uint8_t *ad_data = nullptr;
  size_t ad_size = 0;
  if (ad) {
    ad_data = ad->data();
    ad_size = ad->size_bytes();
  }

  unsigned long long maclen = 0;
  int status = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
    c.data(),
    mac.data(),
    &maclen,
    m.data(),
    m.size_bytes(),
    ad_data,
    ad_size,
    nullptr,
    npub.data(),
    k.data()
  );

  if (status < 0) return status;

  return maclen;
}

static inline int
sn_crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> mac,
  std::optional<js_typedarray_span_t<>> ad,
  js_typedarray_span_t<> npub,
  js_typedarray_span_t<> k
) {
  assert(m.size_bytes() == c.size_bytes());
  assert(mac.size_bytes() == crypto_aead_xchacha20poly1305_ietf_ABYTES);
  assert(npub.size_bytes() == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  assert(k.size_bytes() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

  uint8_t *ad_data = nullptr;
  size_t ad_size = 0;
  if (ad) {
    ad_data = ad->data();
    ad_size = ad->size_bytes();
  }

  int status = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
    m.data(),
    nullptr,
    c.data(),
    c.size_bytes(),
    mac.data(),
    ad_data,
    ad_size,
    npub.data(),
    k.data()
  );

  return status;
}

static inline void
sn_crypto_aead_chacha20poly1305_ietf_keygen(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> k
) {
  assert(k.size_bytes() == crypto_aead_chacha20poly1305_ietf_KEYBYTES);

  crypto_aead_chacha20poly1305_ietf_keygen(k.data());
}

static inline uint64_t
sn_crypto_aead_chacha20poly1305_ietf_encrypt(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m,
  std::optional<js_typedarray_span_t<>> ad,
  js_typedarray_span_t<> npub,
  js_typedarray_span_t<> k
) {
  assert(c.size_bytes() == m.size_bytes() + crypto_aead_chacha20poly1305_ietf_ABYTES);
  assert(c.size_bytes() <= 0xffffffff);
  assert(npub.size_bytes() == crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  assert(k.size_bytes() == crypto_aead_chacha20poly1305_ietf_KEYBYTES);

  uint8_t *ad_data = nullptr;
  size_t ad_size = 0;
  if (ad) {
    ad_data = ad->data();
    ad_size = ad->size_bytes();
  }

  unsigned long long clen = 0;
  int status = crypto_aead_chacha20poly1305_ietf_encrypt(
    c.data(),
    &clen,
    m.data(),
    m.size_bytes(),
    ad_data,
    ad_size,
    nullptr,
    npub.data(),
    k.data()
  );

  if (status < 0) return status;

  return clen;
}

static inline uint64_t
sn_crypto_aead_chacha20poly1305_ietf_decrypt(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> c,
  std::optional<js_typedarray_span_t<>> ad,
  js_typedarray_span_t<> npub,
  js_typedarray_span_t<> k
) {
  assert(m.size_bytes() == c.size_bytes() - crypto_aead_chacha20poly1305_ietf_ABYTES);
  assert(m.size_bytes() <= 0xffffffff);
  assert(npub.size_bytes() == crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  assert(k.size_bytes() == crypto_aead_chacha20poly1305_ietf_KEYBYTES);

  uint8_t *ad_data = nullptr;
  size_t ad_size = 0;
  if (ad) {
    ad_data = ad->data();
    ad_size = ad->size_bytes();
  }

  unsigned long long mlen = 0;
  int status = crypto_aead_chacha20poly1305_ietf_decrypt(
    m.data(),
    &mlen,
    nullptr,
    c.data(),
    c.size_bytes(),
    ad_data,
    ad_size,
    npub.data(),
    k.data()
  );

  if (status < 0) return status;

  return mlen;
}

static inline uint64_t
sn_crypto_aead_chacha20poly1305_ietf_encrypt_detached(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> mac,
  js_typedarray_span_t<> m,
  std::optional<js_typedarray_span_t<>> ad,
  js_typedarray_span_t<> npub,
  js_typedarray_span_t<> k
) {
  assert(c.size_bytes() == m.size_bytes());
  assert(mac.size_bytes() == crypto_aead_chacha20poly1305_ietf_ABYTES);
  assert(npub.size_bytes() == crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  assert(k.size_bytes() == crypto_aead_chacha20poly1305_ietf_KEYBYTES);

  uint8_t *ad_data = nullptr;
  size_t ad_size = 0;
  if (ad) {
    ad_data = ad->data();
    ad_size = ad->size_bytes();
  }

  unsigned long long maclen = 0;
  int status = crypto_aead_chacha20poly1305_ietf_encrypt_detached(
    c.data(),
    mac.data(),
    &maclen,
    m.data(),
    m.size_bytes(),
    ad_data,
    ad_size,
    nullptr,
    npub.data(),
    k.data()
  );

  if (status < 0) return status;

  return maclen;
}

static inline int
sn_crypto_aead_chacha20poly1305_ietf_decrypt_detached(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> mac,
  std::optional<js_typedarray_span_t<>> ad,
  js_typedarray_span_t<> npub,
  js_typedarray_span_t<> k
) {
  assert(m.size_bytes() == c.size_bytes());
  assert(mac.size_bytes() == crypto_aead_chacha20poly1305_ietf_ABYTES);
  assert(npub.size_bytes() == crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  assert(k.size_bytes() == crypto_aead_chacha20poly1305_ietf_KEYBYTES);

  uint8_t *ad_data = nullptr;
  size_t ad_size = 0;
  if (ad) {
    ad_data = ad->data();
    ad_size = ad->size_bytes();
  }

  return crypto_aead_chacha20poly1305_ietf_decrypt_detached(
    m.data(),
    nullptr,
    c.data(),
    c.size_bytes(),
    mac.data(),
    ad_data,
    ad_size,
    npub.data(),
    k.data()
  );
}

static inline void
sn_crypto_secretstream_xchacha20poly1305_keygen(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_span_t k,
  uint32_t k_offset,
  uint32_t k_len
) {
  assert_bounds(k);
  assert(k_len == crypto_secretstream_xchacha20poly1305_KEYBYTES);

  crypto_secretstream_xchacha20poly1305_keygen(&k[k_offset]);
}

static inline int
sn_crypto_secretstream_xchacha20poly1305_init_push(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_span_t state,
  uint32_t state_offset,
  uint32_t state_len,

  js_arraybuffer_span_t header,
  uint32_t header_offset,
  uint32_t header_len,

  js_arraybuffer_span_t k,
  uint32_t k_offset,
  uint32_t k_len
) {
  assert_bounds(state);
  assert_bounds(header);
  assert_bounds(k);

  assert(state_len == sizeof(crypto_secretstream_xchacha20poly1305_state));
  auto state_data = reinterpret_cast<crypto_secretstream_xchacha20poly1305_state *>(&state[state_offset]);

  assert(header_len == crypto_secretstream_xchacha20poly1305_HEADERBYTES);
  assert(k_len == crypto_secretstream_xchacha20poly1305_KEYBYTES);

  return crypto_secretstream_xchacha20poly1305_init_push(state_data, &header[header_offset], &k[k_offset]);
}

static inline uint64_t
sn_crypto_secretstream_xchacha20poly1305_push(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_span_t state,
  uint32_t state_offset,
  uint32_t state_len,

  js_arraybuffer_span_t c,
  uint32_t c_offset,
  uint32_t c_len,

  js_arraybuffer_span_t m,
  uint32_t m_offset,
  uint32_t m_len,

  js_arraybuffer_span_t ad,
  uint32_t ad_offset,
  uint32_t ad_len,

  uint32_t tag
) {
  assert_bounds(state);
  assert_bounds(c);
  assert_bounds(m);

  assert(state_len == sizeof(crypto_secretstream_xchacha20poly1305_state));
  auto state_data = reinterpret_cast<crypto_secretstream_xchacha20poly1305_state *>(&state[state_offset]);

  // next-line kept for future rewrites (js_number is always less than u64 constant);
  // assert(m_len <= crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX);
  assert(c_len == m_len + crypto_secretstream_xchacha20poly1305_ABYTES);
  assert(c_len <= 0xffffffff && "32bit integer");

  uint8_t *ad_data = NULL;
  if (ad_len) {
    assert_bounds(ad);
    ad_data = &ad[ad_offset];
  }

  unsigned long long clen = 0;

  int res = crypto_secretstream_xchacha20poly1305_push(state_data, &c[c_offset], &clen, &m[m_offset], m_len, ad_data, ad_len, tag);
  if (res < 0) return -1;

  return clen;
}

static inline int
sn_crypto_secretstream_xchacha20poly1305_init_pull(
  js_env_t *,
  js_receiver_t,

  js_arraybuffer_span_t state,
  uint32_t state_offset,
  uint32_t state_len,

  js_arraybuffer_span_t header,
  uint32_t header_offset,
  uint32_t header_len,

  js_arraybuffer_span_t k,
  uint32_t k_offset,
  uint32_t k_len
) {
  assert_bounds(state);
  assert_bounds(header);
  assert_bounds(k);

  assert(state_len == sizeof(crypto_secretstream_xchacha20poly1305_state));
  auto state_data = reinterpret_cast<crypto_secretstream_xchacha20poly1305_state *>(&state[state_offset]);

  assert(header_len == crypto_secretstream_xchacha20poly1305_HEADERBYTES);
  assert(k_len == crypto_secretstream_xchacha20poly1305_KEYBYTES);

  return crypto_secretstream_xchacha20poly1305_init_pull(state_data, &header[header_offset], &k[k_offset]);
}

static inline uint64_t
sn_crypto_secretstream_xchacha20poly1305_pull(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_span_t state,
  uint32_t state_offset,
  uint32_t state_len,

  js_arraybuffer_span_t m,
  uint32_t m_offset,
  uint32_t m_len,

  js_arraybuffer_span_t tag,
  uint32_t tag_offset,
  uint32_t tag_len,

  js_arraybuffer_span_t c,
  uint32_t c_offset,
  uint32_t c_len,

  js_arraybuffer_span_t ad,
  uint32_t ad_offset,
  uint32_t ad_len
) {
  assert_bounds(state);
  assert_bounds(m);
  assert_bounds(tag);
  assert_bounds(c);

  assert(state_len == sizeof(crypto_secretstream_xchacha20poly1305_state));
  auto state_data = reinterpret_cast<crypto_secretstream_xchacha20poly1305_state *>(&state[state_offset]);

  assert(c_len >= crypto_secretstream_xchacha20poly1305_ABYTES);
  assert(tag_len == 1);
  assert(m_len == c_len - crypto_secretstream_xchacha20poly1305_ABYTES);
  assert(m_len <= 0xffffffff);

  uint8_t *ad_data = NULL;
  if (ad_len) {
    assert_bounds(ad);
    ad_data = &ad[ad_offset];
  }

  unsigned long long mlen = 0;

  int res = crypto_secretstream_xchacha20poly1305_pull(state_data, &m[m_offset], &mlen, &tag[tag_offset], &c[c_offset], c_len, ad_data, ad_len);
  if (res < 0) return -1;

  return mlen;
}

static inline void
sn_crypto_secretstream_xchacha20poly1305_rekey(
  js_env_t *,
  js_receiver_t,

  js_arraybuffer_span_t state,
  uint32_t state_offset,
  uint32_t state_len
) {
  assert_bounds(state);

  assert(state_len == sizeof(crypto_secretstream_xchacha20poly1305_state));
  auto state_data = reinterpret_cast<crypto_secretstream_xchacha20poly1305_state *>(&state[state_offset]);

  crypto_secretstream_xchacha20poly1305_rekey(state_data);
}

struct sn_async_task_t {
  uv_work_t task;
  js_env_t *env;
  js_persistent_t<js_function_t<void, int>> cb;
  int code;
};

struct sn_async_pwhash_request : sn_async_task_t {
  js_persistent_t<js_arraybuffer_t> out_ref;
  std::span<uint8_t> out;

  js_persistent_t<js_arraybuffer_t> pwd_ref;
  std::span<char> pwd;

  js_persistent_t<js_arraybuffer_t> salt_ref;
  std::span<uint8_t> salt;

  uint64_t opslimit;
  size_t memlimit;
  int alg;
};

static void
async_pwhash_execute(uv_work_t *uv_req) {
  auto req = reinterpret_cast<sn_async_pwhash_request *>(uv_req);
  req->code = crypto_pwhash(
    req->out.data(),
    req->out.size(),
    req->pwd.data(),
    req->pwd.size(),
    req->salt.data(),
    req->opslimit,
    req->memlimit,
    req->alg
  );
}

static void
async_pwhash_complete(uv_work_t *uv_req, int status) {
  int err;

  auto req = reinterpret_cast<sn_async_pwhash_request *>(uv_req);

  js_handle_scope_t *scope;
  err = js_open_handle_scope(req->env, &scope);
  assert(err == 0);

  js_function_t<void, int> callback;
  err = js_get_reference_value(req->env, req->cb, callback);
  assert(err == 0);

  err = js_call_function_with_checkpoint(req->env, callback, req->code);
  assert(err != js_pending_exception);

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);

  delete req;
}

static inline void
sn_crypto_pwhash_async(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_t out,
  uint32_t out_offset,
  uint32_t out_len,

  js_arraybuffer_t pwd,
  uint32_t pwd_offset,
  uint32_t pwd_len,

  js_arraybuffer_t salt,
  uint32_t salt_offset,
  uint32_t salt_len,

  uint64_t opslimit,
  uint64_t memlimit,
  uint32_t alg,

  js_function_t<void, int> callback
) {
  int err;

  auto *req = new sn_async_pwhash_request;

  req->env = env;

  std::span<uint8_t> out_view;
  err = js_get_arraybuffer_info(env, out, out_view);
  assert(err == 0);
  assert(out_offset + out_len <= out_view.size());

  req->out = {&out_view[out_offset], out_len};

  std::span<char> pwd_view;
  err = js_get_arraybuffer_info(env, pwd, pwd_view);
  assert(err == 0);
  assert(pwd_offset + pwd_len <= pwd_view.size());

  req->pwd = {&pwd_view[pwd_offset], pwd_len};

  std::span<uint8_t> salt_view;
  err = js_get_arraybuffer_info(env, salt, salt_view);
  assert(err == 0);
  assert(salt_offset + salt_len <= salt_view.size());

  req->salt = {&salt_view[salt_offset], salt_len};

  err = js_create_reference(env, out, req->out_ref);
  assert(err == 0);
  err = js_create_reference(env, pwd, req->pwd_ref);
  assert(err == 0);
  err = js_create_reference(env, salt, req->salt_ref);
  assert(err == 0);

  req->opslimit = opslimit;
  req->memlimit = memlimit;
  req->alg = alg;

  err = js_create_reference(env, callback, req->cb);
  assert(err == 0);

  uv_loop_t *loop;
  err = js_get_env_loop(env, &loop);
  assert(err == 0);

  err = uv_queue_work(loop, &req->task, async_pwhash_execute, async_pwhash_complete);
  assert(err == 0);
}

struct sn_async_pwhash_str_request : sn_async_task_t {
  js_persistent_t<js_arraybuffer_t> out_ref;
  std::span<char> out;

  js_persistent_t<js_arraybuffer_t> pwd_ref;
  std::span<char> pwd;

  uint64_t opslimit;
  size_t memlimit;
};

static void
async_pwhash_str_execute(uv_work_t *uv_req) {
  auto *req = reinterpret_cast<sn_async_pwhash_str_request *>(uv_req);
  req->code = crypto_pwhash_str(
    req->out.data(),
    req->pwd.data(),
    req->pwd.size(),
    req->opslimit,
    req->memlimit
  );
}

static void
async_pwhash_str_complete(uv_work_t *uv_req, int status) {
  int err;

  auto *req = reinterpret_cast<sn_async_pwhash_str_request *>(uv_req);

  js_handle_scope_t *scope;
  err = js_open_handle_scope(req->env, &scope);
  assert(err == 0);

  js_function_t<void, int> callback;
  err = js_get_reference_value(req->env, req->cb, callback);
  assert(err == 0);

  err = js_call_function_with_checkpoint(req->env, callback, req->code);
  assert(err != js_pending_exception);

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);

  delete req;
}

static inline void
sn_crypto_pwhash_str_async(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_t out,
  uint32_t out_offset,
  uint32_t out_len,

  js_arraybuffer_t pwd,
  uint32_t pwd_offset,
  uint32_t pwd_len,

  uint64_t opslimit,
  uint64_t memlimit,
  js_function_t<void, int> callback
) {
  int err;

  auto *req = new sn_async_pwhash_str_request;

  req->env = env;

  std::span<char> out_view;
  err = js_get_arraybuffer_info(env, out, out_view);
  assert(err == 0);
  assert(out_offset + out_len <= out_view.size());

  req->out = {&out_view[out_offset], out_len};

  std::span<char> pwd_view;
  err = js_get_arraybuffer_info(env, pwd, pwd_view);
  assert(err == 0);
  assert(pwd_offset + pwd_len <= pwd_view.size());

  req->pwd = {&pwd_view[pwd_offset], pwd_len};

  req->opslimit = opslimit;
  req->memlimit = memlimit;

  err = js_create_reference(env, out, req->out_ref);
  assert(err == 0);
  err = js_create_reference(env, pwd, req->pwd_ref);
  assert(err == 0);

  err = js_create_reference(env, callback, req->cb);
  assert(err == 0);

  uv_loop_t *loop;
  err = js_get_env_loop(env, &loop);
  assert(err == 0);

  err = uv_queue_work(loop, &req->task, async_pwhash_str_execute, async_pwhash_str_complete);
  assert(err == 0);
}

struct sn_async_pwhash_str_verify_request : sn_async_task_t {
  js_persistent_t<js_arraybuffer_t> str_ref;
  std::span<char> str;

  js_persistent_t<js_arraybuffer_t> pwd_ref;
  std::span<char> pwd;
};

static void
async_pwhash_str_verify_execute(uv_work_t *uv_req) {
  auto *req = reinterpret_cast<sn_async_pwhash_str_verify_request *>(uv_req);
  req->code = crypto_pwhash_str_verify(req->str.data(), req->pwd.data(), req->pwd.size());
}

static void
async_pwhash_str_verify_complete(uv_work_t *uv_req, int status) {
  int err;

  auto *req = reinterpret_cast<sn_async_pwhash_str_verify_request *>(uv_req);

  js_handle_scope_t *scope;
  err = js_open_handle_scope(req->env, &scope);
  assert(err == 0);

  js_function_t<void, int> callback;
  err = js_get_reference_value(req->env, req->cb, callback);
  assert(err == 0);

  // Due to the way that crypto_pwhash_str_verify signals error different
  // from a verification mismatch, we will count all errors as mismatch.
  // The other possible error is wrong argument sizes, which is protected
  // by macros above;
  err = js_call_function_with_checkpoint(req->env, callback, req->code);
  assert(err != js_pending_exception);

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);

  delete req;
}

static inline void
sn_crypto_pwhash_str_verify_async(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_t str,
  uint32_t str_offset,
  uint32_t str_len,

  js_arraybuffer_t pwd,
  uint32_t pwd_offset,
  uint32_t pwd_len,

  js_function_t<void, int> callback
) {
  int err;

  auto *req = new sn_async_pwhash_str_verify_request;
  req->env = env;

  std::span<char> str_view;
  err = js_get_arraybuffer_info(env, str, str_view);
  assert(err == 0);
  assert(str_offset + str_len <= str_view.size());

  req->str = {&str_view[str_offset], str_len};

  std::span<char> pwd_view;
  err = js_get_arraybuffer_info(env, pwd, pwd_view);
  assert(err == 0);
  assert(pwd_offset + pwd_len <= pwd_view.size());

  req->pwd = {&pwd_view[pwd_offset], pwd_len};

  err = js_create_reference(env, str, req->str_ref);
  assert(err == 0);
  err = js_create_reference(env, pwd, req->pwd_ref);
  assert(err == 0);
  err = js_create_reference(env, callback, req->cb);
  assert(err == 0);

  uv_loop_t *loop;
  err = js_get_env_loop(env, &loop);
  assert(err == 0);

  err = uv_queue_work(loop, &req->task, async_pwhash_str_verify_execute, async_pwhash_str_verify_complete);
  assert(err == 0);
}

struct sn_async_pwhash_scryptsalsa208sha256_request : sn_async_task_t {
  js_persistent_t<js_arraybuffer_t> out_ref;
  std::span<uint8_t> out;

  js_persistent_t<js_arraybuffer_t> pwd_ref;
  std::span<char> pwd;

  js_persistent_t<js_arraybuffer_t> salt_ref;
  std::span<uint8_t> salt;

  uint64_t opslimit;
  size_t memlimit;
};

static void
async_pwhash_scryptsalsa208sha256_execute(uv_work_t *uv_req) {
  auto *req = reinterpret_cast<sn_async_pwhash_scryptsalsa208sha256_request *>(uv_req);

  req->code = crypto_pwhash_scryptsalsa208sha256(
    req->out.data(),
    req->out.size(),
    req->pwd.data(),
    req->pwd.size(),
    req->salt.data(),
    req->opslimit,
    req->memlimit
  );
}

static void
async_pwhash_scryptsalsa208sha256_complete(uv_work_t *uv_req, int status) {
  int err;

  auto *req = reinterpret_cast<sn_async_pwhash_scryptsalsa208sha256_request *>(uv_req);

  js_handle_scope_t *scope;
  err = js_open_handle_scope(req->env, &scope);
  assert(err == 0);

  js_function_t<void, int> callback;
  err = js_get_reference_value(req->env, req->cb, callback);
  assert(err == 0);

  err = js_call_function_with_checkpoint(req->env, callback, req->code);
  assert(err != js_pending_exception);

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);

  delete req;
}

static inline void
sn_crypto_pwhash_scryptsalsa208sha256_async(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_t out,
  uint32_t out_offset,
  uint32_t out_len,

  js_arraybuffer_t pwd,
  uint32_t pwd_offset,
  uint32_t pwd_len,

  js_arraybuffer_t salt,
  uint32_t salt_offset,
  uint32_t salt_len,

  uint64_t opslimit,
  uint64_t memlimit,

  js_function_t<void, int> callback
) {
  int err;

  auto *req = new sn_async_pwhash_scryptsalsa208sha256_request;

  req->env = env;

  std::span<uint8_t> out_view;
  err = js_get_arraybuffer_info(env, out, out_view);
  assert(err == 0);
  assert(out_offset + out_len <= out_view.size());

  req->out = {&out_view[out_offset], out_len};

  std::span<char> pwd_view;
  err = js_get_arraybuffer_info(env, pwd, pwd_view);
  assert(err == 0);
  assert(pwd_offset + pwd_len <= pwd_view.size());

  req->pwd = {&pwd_view[pwd_offset], pwd_len};

  std::span<uint8_t> salt_view;
  err = js_get_arraybuffer_info(env, salt, salt_view);
  assert(err == 0);
  assert(salt_offset + salt_len <= salt_view.size());
  assert(salt_len == crypto_pwhash_scryptsalsa208sha256_SALTBYTES);

  req->salt = {&salt_view[salt_offset], salt_len};

  err = js_create_reference(env, out, req->out_ref);
  assert(err == 0);
  err = js_create_reference(env, pwd, req->pwd_ref);
  assert(err == 0);
  err = js_create_reference(env, salt, req->salt_ref);
  assert(err == 0);

  req->opslimit = opslimit;
  req->memlimit = memlimit;

  err = js_create_reference(env, callback, req->cb);
  assert(err == 0);

  uv_loop_t *loop;
  err = js_get_env_loop(env, &loop);
  assert(err == 0);

  err = uv_queue_work(loop, &req->task, async_pwhash_scryptsalsa208sha256_execute, async_pwhash_scryptsalsa208sha256_complete);
  assert(err == 0);
}

struct sn_async_pwhash_scryptsalsa208sha256_str_request : sn_async_task_t {
  js_persistent_t<js_arraybuffer_t> out_ref;
  std::span<char> out;

  js_persistent_t<js_arraybuffer_t> pwd_ref;
  std::span<char> pwd;

  uint64_t opslimit;
  size_t memlimit;
};

static void
async_pwhash_scryptsalsa208sha256_str_execute(uv_work_t *uv_req) {
  auto *req = reinterpret_cast<sn_async_pwhash_scryptsalsa208sha256_str_request *>(uv_req);
  req->code = crypto_pwhash_scryptsalsa208sha256_str(
    req->out.data(),
    req->pwd.data(),
    req->pwd.size(),
    req->opslimit,
    req->memlimit
  );
}

static void
async_pwhash_scryptsalsa208sha256_str_complete(uv_work_t *uv_req, int status) {
  int err;

  auto *req = reinterpret_cast<sn_async_pwhash_scryptsalsa208sha256_str_request *>(uv_req);

  js_handle_scope_t *scope;
  err = js_open_handle_scope(req->env, &scope);
  assert(err == 0);

  js_function_t<void, int> callback;
  err = js_get_reference_value(req->env, req->cb, callback);
  assert(err == 0);

  err = js_call_function_with_checkpoint(req->env, callback, req->code);
  assert(err != js_pending_exception);

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);

  delete req;
}

static inline void
sn_crypto_pwhash_scryptsalsa208sha256_str_async(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_t out,
  uint32_t out_offset,
  uint32_t out_len,

  js_arraybuffer_t pwd,
  uint32_t pwd_offset,
  uint32_t pwd_len,

  uint64_t opslimit,
  uint64_t memlimit,

  js_function_t<void, int> callback
) {
  int err;

  auto *req = new sn_async_pwhash_scryptsalsa208sha256_str_request;

  req->env = env;

  std::span<char> out_view;
  err = js_get_arraybuffer_info(env, out, out_view);
  assert(err == 0);
  assert(out_offset + out_len <= out_view.size());

  req->out = {&out_view[out_offset], out_len};

  std::span<char> pwd_view;
  err = js_get_arraybuffer_info(env, pwd, pwd_view);
  assert(err == 0);
  assert(pwd_offset + pwd_len <= pwd_view.size());

  req->pwd = {&pwd_view[pwd_offset], pwd_len};

  req->opslimit = opslimit;
  req->memlimit = memlimit;

  err = js_create_reference(env, out, req->out_ref);
  assert(err == 0);

  err = js_create_reference(env, out, req->pwd_ref);
  assert(err == 0);

  err = js_create_reference(env, callback, req->cb);
  assert(err == 0);

  uv_loop_t *loop;
  err = js_get_env_loop(env, &loop);
  assert(err == 0);

  err = uv_queue_work(loop, &req->task, async_pwhash_scryptsalsa208sha256_str_execute, async_pwhash_scryptsalsa208sha256_str_complete);
  assert(err == 0);
}

struct sn_async_pwhash_scryptsalsa208sha256_str_verify_request : sn_async_task_t {
  js_persistent_t<js_arraybuffer_t> str_ref;
  std::span<char> str;

  js_persistent_t<js_arraybuffer_t> pwd_ref;
  std::span<char> pwd;
};

static void
async_pwhash_scryptsalsa208sha256_str_verify_execute(uv_work_t *uv_req) {
  auto *req = reinterpret_cast<sn_async_pwhash_scryptsalsa208sha256_str_verify_request *>(uv_req);

  req->code = crypto_pwhash_scryptsalsa208sha256_str_verify(req->str.data(), req->pwd.data(), req->pwd.size());
}

static void
async_pwhash_scryptsalsa208sha256_str_verify_complete(uv_work_t *uv_req, int status) {
  int err;

  auto *req = reinterpret_cast<sn_async_pwhash_scryptsalsa208sha256_str_verify_request *>(uv_req);

  js_handle_scope_t *scope;
  err = js_open_handle_scope(req->env, &scope);
  assert(err == 0);

  js_function_t<void, int> callback;
  err = js_get_reference_value(req->env, req->cb, callback);
  assert(err == 0);

  // Due to the way that crypto_pwhash_scryptsalsa208sha256_str_verify
  // signal serror different from a verification mismatch, we will count
  // all errors as mismatch. The other possible error is wrong argument
  // sizes, which is protected by macros above
  err = js_call_function_with_checkpoint(req->env, callback, req->code);
  assert(err != js_pending_exception);

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);

  delete req;
}

static inline void
sn_crypto_pwhash_scryptsalsa208sha256_str_verify_async(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_t str,
  uint32_t str_offset,
  uint32_t str_len,

  js_arraybuffer_t pwd,
  uint32_t pwd_offset,
  uint32_t pwd_len,

  js_function_t<void, int> callback
) {
  int err;
  auto *req = new sn_async_pwhash_scryptsalsa208sha256_str_verify_request;

  req->env = env;

  std::span<char> str_view;
  err = js_get_arraybuffer_info(env, str, str_view);
  assert(err == 0);
  assert(str_offset + str_len <= str_view.size());

  req->str = {&str_view[str_offset], str_len};

  std::span<char> pwd_view;
  err = js_get_arraybuffer_info(env, pwd, pwd_view);
  assert(err == 0);
  assert(pwd_offset + pwd_len <= pwd_view.size());

  req->pwd = {&pwd_view[pwd_offset], pwd_len};

  err = js_create_reference(env, str, req->str_ref);
  assert(err == 0);
  err = js_create_reference(env, pwd, req->pwd_ref);
  assert(err == 0);

  err = js_create_reference(env, callback, req->cb);
  assert(err == 0);

  uv_loop_t *loop;
  err = js_get_env_loop(env, &loop);
  assert(err == 0);

  err = uv_queue_work(loop, &req->task, async_pwhash_scryptsalsa208sha256_str_verify_execute, async_pwhash_scryptsalsa208sha256_str_verify_complete);
  assert(err == 0);
}

typedef struct sn_crypto_stream_xor_state {
  unsigned char n[crypto_stream_NONCEBYTES];
  unsigned char k[crypto_stream_KEYBYTES];
  unsigned char next_block[64];
  int remainder;
  uint64_t block_counter;
} sn_crypto_stream_xor_state;

static inline void
sn_crypto_stream_xor_wrap_init(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<sn_crypto_stream_xor_state, 1> state,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(n.size_bytes() == crypto_stream_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_KEYBYTES);

  state->remainder = 0;
  state->block_counter = 0;
  memcpy(state->n, n.data(), crypto_stream_NONCEBYTES);
  memcpy(state->k, k.data(), crypto_stream_KEYBYTES);
}

static inline void
sn_crypto_stream_xor_wrap_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<sn_crypto_stream_xor_state, 1> state,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m
) {
  assert(c.size_bytes() == m.size_bytes());

  auto next_block = state->next_block;

  size_t m_size = m.size_bytes();
  auto *c_ptr = c.data();
  auto *m_ptr = m.data();

  if (state->remainder) {
    uint64_t offset = 0;
    int rem = state->remainder;

    while (rem < 64 && offset < m_size) {
      c_ptr[offset] = next_block[rem] ^ m_ptr[offset];
      ++offset;
      ++rem;
    }

    c_ptr += offset;
    m_ptr += offset;
    m_size -= offset;
    state->remainder = (rem == 64) ? 0 : rem;

    if (m_size == 0) return;
  }

  state->remainder = m_size & 63;
  size_t main_len = m_size - state->remainder;

  crypto_stream_xsalsa20_xor_ic(c_ptr, m_ptr, main_len, state->n, state->block_counter, state->k);
  state->block_counter += main_len / 64;

  if (state->remainder) {
    sodium_memzero(next_block + state->remainder, 64 - state->remainder);
    memcpy(next_block, m_ptr + main_len, state->remainder);

    crypto_stream_xsalsa20_xor_ic(
      next_block, next_block, 64, state->n, state->block_counter, state->k
    );
    memcpy(c_ptr + main_len, next_block, state->remainder);

    state->block_counter++;
  }
}

static inline void
sn_crypto_stream_xor_wrap_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<sn_crypto_stream_xor_state, 1> state
) {
  sodium_memzero(state->n, sizeof(state->n));
  sodium_memzero(state->k, sizeof(state->k));
  sodium_memzero(state->next_block, sizeof(state->next_block));
  state->remainder = 0;
}

typedef struct sn_crypto_stream_chacha20_xor_state {
  unsigned char n[crypto_stream_chacha20_NONCEBYTES];
  unsigned char k[crypto_stream_chacha20_KEYBYTES];
  unsigned char next_block[64];
  int remainder;
  uint64_t block_counter;
} sn_crypto_stream_chacha20_xor_state;

static inline void
sn_crypto_stream_chacha20_xor_wrap_init(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<sn_crypto_stream_chacha20_xor_state, 1> state,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(n.size_bytes() == crypto_stream_chacha20_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_chacha20_KEYBYTES);

  state->remainder = 0;
  state->block_counter = 0;
  memcpy(state->n, n.data(), crypto_stream_chacha20_NONCEBYTES);
  memcpy(state->k, k.data(), crypto_stream_chacha20_KEYBYTES);
}

static inline void
sn_crypto_stream_chacha20_xor_wrap_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<sn_crypto_stream_chacha20_xor_state, 1> state,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m
) {
  assert(c.size_bytes() == m.size_bytes());

  auto *next_block = state->next_block;

  size_t m_size = m.size_bytes();
  auto *c_ptr = c.data();
  auto *m_ptr = m.data();

  if (state->remainder) {
    uint64_t offset = 0;
    int rem = state->remainder;

    while (rem < 64 && offset < m_size) {
      c_ptr[offset] = next_block[rem] ^ m_ptr[offset];
      offset++;
      rem++;
    }

    c_ptr += offset;
    m_ptr += offset;
    m_size -= offset;
    state->remainder = (rem == 64) ? 0 : rem;

    if (m_size == 0) return;
  }

  state->remainder = m_size & 63;
  size_t main_len = m_size - state->remainder;

  crypto_stream_chacha20_xor_ic(
    c_ptr, m_ptr, main_len, state->n, state->block_counter, state->k
  );

  state->block_counter += main_len / 64;

  if (state->remainder) {
    sodium_memzero(next_block + state->remainder, 64 - state->remainder);
    memcpy(next_block, m_ptr + main_len, state->remainder);

    crypto_stream_chacha20_xor_ic(
      next_block, next_block, 64, state->n, state->block_counter, state->k
    );
    memcpy(c_ptr + main_len, next_block, state->remainder);

    state->block_counter++;
  }
}

static inline void
sn_crypto_stream_chacha20_xor_wrap_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<sn_crypto_stream_chacha20_xor_state, 1> state
) {
  sodium_memzero(state->n, sizeof(state->n));
  sodium_memzero(state->k, sizeof(state->k));
  sodium_memzero(state->next_block, sizeof(state->next_block));
  state->remainder = 0;
}

typedef struct sn_crypto_stream_chacha20_ietf_xor_state {
  unsigned char n[crypto_stream_chacha20_ietf_NONCEBYTES];
  unsigned char k[crypto_stream_chacha20_ietf_KEYBYTES];
  unsigned char next_block[64];
  int remainder;
  uint64_t block_counter;
} sn_crypto_stream_chacha20_ietf_xor_state;

static inline void
sn_crypto_stream_chacha20_ietf_xor_wrap_init(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<sn_crypto_stream_chacha20_ietf_xor_state, 1> state,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(n.size_bytes() == crypto_stream_chacha20_ietf_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_chacha20_ietf_KEYBYTES);

  state->remainder = 0;
  state->block_counter = 0;
  memcpy(state->n, n.data(), crypto_stream_chacha20_ietf_NONCEBYTES);
  memcpy(state->k, k.data(), crypto_stream_chacha20_ietf_KEYBYTES);
}

static inline void
sn_crypto_stream_chacha20_ietf_xor_wrap_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<sn_crypto_stream_chacha20_ietf_xor_state, 1> state,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m
) {
  assert(c.size_bytes() == m.size_bytes());

  auto *next_block = state->next_block;

  size_t m_size = m.size_bytes();
  auto *c_ptr = c.data();
  auto *m_ptr = m.data();

  if (state->remainder) {
    uint64_t offset = 0;
    int rem = state->remainder;

    while (rem < 64 && offset < m_size) {
      c_ptr[offset] = next_block[rem] ^ m_ptr[offset];
      offset++;
      rem++;
    }

    c_ptr += offset;
    m_ptr += offset;
    m_size -= offset;
    state->remainder = (rem == 64) ? 0 : rem;

    if (m_size == 0) return;
  }

  state->remainder = m_size & 63;
  size_t main_len = m_size - state->remainder;

  crypto_stream_chacha20_ietf_xor_ic(
    c_ptr, m_ptr, main_len, state->n, state->block_counter, state->k
  );

  state->block_counter += main_len / 64;

  if (state->remainder) {
    sodium_memzero(next_block + state->remainder, 64 - state->remainder);
    memcpy(next_block, m_ptr + main_len, state->remainder);

    crypto_stream_chacha20_ietf_xor_ic(
      next_block, next_block, 64, state->n, state->block_counter, state->k
    );
    memcpy(c_ptr + main_len, next_block, state->remainder);

    state->block_counter++;
  }
}

static inline void
sn_crypto_stream_chacha20_ietf_xor_wrap_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<sn_crypto_stream_chacha20_ietf_xor_state, 1> state
) {
  sodium_memzero(state->n, sizeof(state->n));
  sodium_memzero(state->k, sizeof(state->k));
  sodium_memzero(state->next_block, sizeof(state->next_block));
  state->remainder = 0;
}

typedef struct sn_crypto_stream_xchacha20_xor_state {
  unsigned char n[crypto_stream_xchacha20_NONCEBYTES];
  unsigned char k[crypto_stream_xchacha20_KEYBYTES];
  unsigned char next_block[64];
  int remainder;
  uint64_t block_counter;
} sn_crypto_stream_xchacha20_xor_state;

static inline void
sn_crypto_stream_xchacha20_xor_wrap_init(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<sn_crypto_stream_xchacha20_xor_state, 1> state,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(n.size_bytes() == crypto_stream_xchacha20_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_xchacha20_KEYBYTES);

  state->remainder = 0;
  state->block_counter = 0;
  memcpy(state->n, n.data(), crypto_stream_xchacha20_NONCEBYTES);
  memcpy(state->k, k.data(), crypto_stream_xchacha20_KEYBYTES);
}

static inline void
sn_crypto_stream_xchacha20_xor_wrap_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<sn_crypto_stream_xchacha20_xor_state, 1> state,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m
) {
  assert(c.size_bytes() == m.size_bytes());

  auto *next_block = state->next_block;

  size_t m_size = m.size_bytes();
  auto *c_ptr = c.data();
  auto *m_ptr = m.data();

  if (state->remainder) {
    uint64_t offset = 0;
    int rem = state->remainder;

    while (rem < 64 && offset < m_size) {
      c_ptr[offset] = next_block[rem] ^ m_ptr[offset];
      ++offset;
      ++rem;
    }

    c_ptr += offset;
    m_ptr += offset;
    m_size -= offset;
    state->remainder = (rem == 64) ? 0 : rem;

    if (m_size == 0) return;
  }

  state->remainder = m_size & 63;
  size_t main_len = m_size - state->remainder;

  crypto_stream_xchacha20_xor_ic(
    c_ptr, m_ptr, main_len, state->n, state->block_counter, state->k
  );

  state->block_counter += main_len / 64;

  if (state->remainder) {
    sodium_memzero(next_block + state->remainder, 64 - state->remainder);
    memcpy(next_block, m_ptr + main_len, state->remainder);

    crypto_stream_xchacha20_xor_ic(
      next_block, next_block, 64, state->n, state->block_counter, state->k
    );
    memcpy(c_ptr + main_len, next_block, state->remainder);

    state->block_counter++;
  }
}

static inline void
sn_crypto_stream_xchacha20_xor_wrap_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<sn_crypto_stream_xchacha20_xor_state, 1> state
) {
  sodium_memzero(state->n, sizeof(state->n));
  sodium_memzero(state->k, sizeof(state->k));
  sodium_memzero(state->next_block, sizeof(state->next_block));
  state->remainder = 0;
}

typedef struct sn_crypto_stream_salsa20_xor_state {
  unsigned char n[crypto_stream_salsa20_NONCEBYTES];
  unsigned char k[crypto_stream_salsa20_KEYBYTES];
  unsigned char next_block[64];
  int remainder;
  uint64_t block_counter;
} sn_crypto_stream_salsa20_xor_state;

static inline void
sn_crypto_stream_salsa20_xor_wrap_init(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<sn_crypto_stream_salsa20_xor_state, 1> state,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(n.size_bytes() == crypto_stream_salsa20_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_salsa20_KEYBYTES);

  state->remainder = 0;
  state->block_counter = 0;
  memcpy(state->n, n.data(), crypto_stream_salsa20_NONCEBYTES);
  memcpy(state->k, k.data(), crypto_stream_salsa20_KEYBYTES);
}

static inline void
sn_crypto_stream_salsa20_xor_wrap_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<sn_crypto_stream_salsa20_xor_state, 1> state,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m
) {
  assert(c.size_bytes() == m.size_bytes());

  auto *next_block = state->next_block;

  size_t m_size = m.size_bytes();
  auto *c_ptr = c.data();
  auto *m_ptr = m.data();

  if (state->remainder) {
    uint64_t offset = 0;
    int rem = state->remainder;

    while (rem < 64 && offset < m_size) {
      c_ptr[offset] = next_block[rem] ^ m_ptr[offset];
      ++offset;
      ++rem;
    }

    c_ptr += offset;
    m_ptr += offset;
    m_size -= offset;
    state->remainder = (rem == 64) ? 0 : rem;

    if (m_size == 0) return;
  }

  state->remainder = m_size & 63;
  size_t main_len = m_size - state->remainder;

  crypto_stream_salsa20_xor_ic(
    c_ptr, m_ptr, main_len, state->n, state->block_counter, state->k
  );

  state->block_counter += main_len / 64;

  if (state->remainder) {
    sodium_memzero(next_block + state->remainder, 64 - state->remainder);
    memcpy(next_block, m_ptr + main_len, state->remainder);

    crypto_stream_salsa20_xor_ic(
      next_block, next_block, 64, state->n, state->block_counter, state->k
    );
    memcpy(c_ptr + main_len, next_block, state->remainder);

    state->block_counter++;
  }
}

static inline void
sn_crypto_stream_salsa20_xor_wrap_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_of_t<sn_crypto_stream_salsa20_xor_state, 1> state
) {
  sodium_memzero(state->n, sizeof(state->n));
  sodium_memzero(state->k, sizeof(state->k));
  sodium_memzero(state->next_block, sizeof(state->next_block));
  state->remainder = 0;
}

// Experimental API

static inline void
sn_extension_tweak_ed25519_base(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> p,
  js_typedarray_span_t<> ns
) {
  assert(n.size_bytes() == sn__extension_tweak_ed25519_SCALARBYTES);
  assert(p.size_bytes() == sn__extension_tweak_ed25519_BYTES);

  sn__extension_tweak_ed25519_base(p.data(), n.data(), ns.data(), ns.size_bytes());
}

static inline int
sn_extension_tweak_ed25519_sign_detached(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> sig,
  js_typedarray_span_t<> m,
  js_typedarray_span_t<> scalar,
  std::optional<js_typedarray_span_t<>> pk
) {
  assert(sig.size_bytes() == crypto_sign_BYTES);
  assert(scalar.size_bytes() == sn__extension_tweak_ed25519_SCALARBYTES);

  uint8_t *pk_data = nullptr;
  if (pk) {
    assert(pk->size_bytes() == crypto_sign_PUBLICKEYBYTES);
    pk_data = pk->data();
  }

  return sn__extension_tweak_ed25519_sign_detached(
    sig.data(),
    nullptr,
    m.data(),
    m.size_bytes(),
    scalar.data(),
    pk_data
  );
}

static inline void
sn_extension_tweak_ed25519_sk_to_scalar(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> sk
) {
  assert(n.size_bytes() == sn__extension_tweak_ed25519_SCALARBYTES);
  assert(sk.size_bytes() == crypto_sign_SECRETKEYBYTES);

  sn__extension_tweak_ed25519_sk_to_scalar(n.data(), sk.data());
}

static inline void
sn_extension_tweak_ed25519_scalar(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> scalar_out,
  js_typedarray_span_t<> scalar,
  js_typedarray_span_t<> ns
) {
  assert(scalar_out.size_bytes() == sn__extension_tweak_ed25519_SCALARBYTES);
  assert(scalar.size_bytes() == sn__extension_tweak_ed25519_SCALARBYTES);

  sn__extension_tweak_ed25519_scalar(scalar_out.data(), scalar.data(), ns.data(), ns.size_bytes());
}

static inline int
sn_extension_tweak_ed25519_pk(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> tpk,
  js_typedarray_span_t<> pk,
  js_typedarray_span_t<> ns
) {
  assert(tpk.size_bytes() == crypto_sign_PUBLICKEYBYTES);
  assert(pk.size_bytes() == crypto_sign_PUBLICKEYBYTES);

  return sn__extension_tweak_ed25519_pk(tpk.data(), pk.data(), ns.data(), ns.size_bytes());
}

static inline void
sn_extension_tweak_ed25519_keypair(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> pk,
  js_typedarray_span_t<> scalar_out,
  js_typedarray_span_t<> scalar_in,
  js_typedarray_span_t<> ns
) {
  assert(pk.size_bytes() == sn__extension_tweak_ed25519_BYTES);
  assert(scalar_out.size_bytes() == sn__extension_tweak_ed25519_SCALARBYTES);
  assert(scalar_in.size_bytes() == sn__extension_tweak_ed25519_SCALARBYTES);

  sn__extension_tweak_ed25519_keypair(
    pk.data(),
    scalar_out.data(),
    scalar_in.data(),
    ns.data(),
    ns.size_bytes()
  );
}

static inline void
sn_extension_tweak_ed25519_scalar_add(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> scalar_out,
  js_typedarray_span_t<> scalar,
  js_typedarray_span_t<> n
) {
  assert(scalar_out.size_bytes() == sn__extension_tweak_ed25519_SCALARBYTES);
  assert(scalar.size_bytes() == sn__extension_tweak_ed25519_SCALARBYTES);
  assert(n.size_bytes() == sn__extension_tweak_ed25519_SCALARBYTES);

  sn__extension_tweak_ed25519_scalar_add(scalar_out.data(), scalar.data(), n.data());
}

static inline int
sn_extension_tweak_ed25519_pk_add(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> tpk,
  js_typedarray_span_t<> pk,
  js_typedarray_span_t<> p
) {
  assert(tpk.size_bytes() == crypto_sign_PUBLICKEYBYTES);
  assert(pk.size_bytes() == crypto_sign_PUBLICKEYBYTES);
  assert(p.size_bytes() == crypto_sign_PUBLICKEYBYTES);

  return sn__extension_tweak_ed25519_pk_add(tpk.data(), pk.data(), p.data());
}

static inline int
sn_extension_tweak_ed25519_keypair_add(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> pk,
  js_typedarray_span_t<> scalar_out,
  js_typedarray_span_t<> scalar_in,
  js_typedarray_span_t<> tweak
) {
  assert(pk.size_bytes() == sn__extension_tweak_ed25519_BYTES);
  assert(scalar_out.size_bytes() == sn__extension_tweak_ed25519_SCALARBYTES);
  assert(scalar_in.size_bytes() == sn__extension_tweak_ed25519_SCALARBYTES);
  assert(tweak.size_bytes() == sn__extension_tweak_ed25519_SCALARBYTES);

  return sn__extension_tweak_ed25519_keypair_add(
    pk.data(),
    scalar_out.data(),
    scalar_in.data(),
    tweak.data()
  );
}

static inline int
sn_extension_pbkdf2_sha512(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> out,
  js_typedarray_span_t<> passwd,
  js_typedarray_span_t<> salt,
  uint64_t iter,
  uint64_t outlen
) {

  assert(iter >= sn__extension_pbkdf2_sha512_ITERATIONS_MIN);
  assert(outlen <= sn__extension_pbkdf2_sha512_BYTES_MAX);
  assert(out.size_bytes() >= static_cast<size_t>(outlen));

  return sn__extension_pbkdf2_sha512(
    passwd.data(),
    passwd.size_bytes(),
    salt.data(),
    salt.size_bytes(),
    iter,
    out.data(),
    outlen
  );
}

struct sn_async_pbkdf2_sha512_request : sn_async_task_t {
  js_persistent_t<js_arraybuffer_t> out_ref;
  std::span<uint8_t> out;

  size_t outlen;

  js_persistent_t<js_arraybuffer_t> pwd_ref;
  std::span<uint8_t> pwd;

  js_persistent_t<js_arraybuffer_t> salt_ref;
  std::span<uint8_t> salt;

  uint64_t iter;
};

static void
async_pbkdf2_sha512_execute(uv_work_t *uv_req) {
  auto *req = reinterpret_cast<sn_async_pbkdf2_sha512_request *>(uv_req);

  req->code = sn__extension_pbkdf2_sha512(
    req->pwd.data(),
    req->pwd.size(),
    req->salt.data(),
    req->salt.size(),
    req->iter,
    req->out.data(),
    req->outlen
  );
}

static void
async_pbkdf2_sha512_complete(uv_work_t *uv_req, int status) {
  int err;

  auto *req = reinterpret_cast<sn_async_pbkdf2_sha512_request *>(uv_req);

  js_handle_scope_t *scope;
  err = js_open_handle_scope(req->env, &scope);
  assert(err == 0);

  js_function_t<void, int> callback;
  err = js_get_reference_value(req->env, req->cb, callback);
  assert(err == 0);

  err = js_call_function_with_checkpoint(req->env, callback, req->code);
  assert(err != js_pending_exception);

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);

  delete req;
}

static inline void
sn_extension_pbkdf2_sha512_async(
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_t out,
  uint32_t out_offset,
  uint32_t out_len,

  js_arraybuffer_t pwd,
  uint32_t pwd_offset,
  uint32_t pwd_len,

  js_arraybuffer_t salt,
  uint32_t salt_offset,
  uint32_t salt_len,

  uint64_t iter,
  uint64_t outlen,

  js_function_t<void, int> callback
) {
  int err;

  auto *req = new sn_async_pbkdf2_sha512_request;

  req->env = env;

  std::span<uint8_t> out_view;
  err = js_get_arraybuffer_info(env, out, out_view);
  assert(err == 0);
  assert(out_offset + out_len <= out_view.size());

  req->out = {&out_view[out_offset], out_len};

  std::span<uint8_t> pwd_view;
  err = js_get_arraybuffer_info(env, pwd, pwd_view);
  assert(err == 0);
  assert(pwd_offset + pwd_len <= pwd_view.size());

  req->pwd = {&pwd_view[pwd_offset], pwd_len};

  std::span<uint8_t> salt_view;
  err = js_get_arraybuffer_info(env, salt, salt_view);
  assert(err == 0);
  assert(salt_offset + salt_len <= salt_view.size());

  req->salt = {&salt_view[salt_offset], salt_len};

  req->iter = iter;
  req->outlen = outlen;

  err = js_create_reference(env, out, req->out_ref);
  assert(err == 0);
  err = js_create_reference(env, pwd, req->pwd_ref);
  assert(err == 0);
  err = js_create_reference(env, salt, req->salt_ref);
  assert(err == 0);
  err = js_create_reference(env, callback, req->cb);
  assert(err == 0);

  uv_loop_t *loop;
  err = js_get_env_loop(env, &loop);
  assert(err == 0);

  err = uv_queue_work(loop, &req->task, async_pbkdf2_sha512_execute, async_pbkdf2_sha512_complete);
  assert(err == 0);
}

js_value_t *
sodium_native_exports(js_env_t *env, js_value_t *exports) {
  int err;

  err = sodium_init();
  assert(err == 0 && "sodium init");

  js_object_t _exports = static_cast<js_object_t>(exports);

#define V_FUNCTION(name, fn) \
  err = js_set_property<fn>(env, _exports, name); \
  assert(err == 0);

#define V_FUNCTION_NOSCOPE(name, fn) \
  err = js_set_property<fn, js_function_options_t{.scoped = false}>(env, _exports, name); \
  assert(err == 0);

#define V_UINT32(name, constant) \
  err = js_set_property(env, _exports, name, static_cast<uint32_t>(constant)); \
  assert(err == 0);

#define V_UINT64(name, constant) \
  assert(constant >= 0); \
  err = js_set_property(env, _exports, name, static_cast<int64_t>(std::min<uint64_t>(constant, 0x1fffffffffffffULL))); \
  assert(err == 0);

#define V_STRING(name, str) \
  err = js_set_property(env, _exports, name, str); \
  assert(err == 0);

  // memory

  V_FUNCTION("sodium_memzero", sn_sodium_memzero);
  V_FUNCTION("sodium_mlock", sn_sodium_mlock);
  V_FUNCTION("sodium_munlock", sn_sodium_munlock);
  V_FUNCTION("sodium_malloc", sn_sodium_malloc);
  V_FUNCTION("sodium_free", sn_sodium_free);
  V_FUNCTION("sodium_mprotect_noaccess", sn_sodium_mprotect_noaccess);
  V_FUNCTION("sodium_mprotect_readonly", sn_sodium_mprotect_readonly);
  V_FUNCTION("sodium_mprotect_readwrite", sn_sodium_mprotect_readwrite);

  // randombytes

  V_FUNCTION_NOSCOPE("randombytes_buf", sn_randombytes_buf);
  V_FUNCTION_NOSCOPE("randombytes_buf_deterministic", sn_randombytes_buf_deterministic);
  V_FUNCTION_NOSCOPE("randombytes_random", sn_randombytes_random);
  V_FUNCTION_NOSCOPE("randombytes_uniform", sn_randombytes_uniform);

  V_UINT32("randombytes_SEEDBYTES", randombytes_SEEDBYTES);

  // sodium helpers

  V_FUNCTION("sodium_memcmp", sn_sodium_memcmp);
  V_FUNCTION("sodium_increment", sn_sodium_increment);
  V_FUNCTION("sodium_add", sn_sodium_add);
  V_FUNCTION("sodium_sub", sn_sodium_sub);
  V_FUNCTION("sodium_compare", sn_sodium_compare);
  V_FUNCTION("sodium_is_zero", sn_sodium_is_zero);
  V_FUNCTION("sodium_pad", sn_sodium_pad);
  V_FUNCTION("sodium_unpad", sn_sodium_unpad);

  // crypto_aead

  V_FUNCTION("crypto_aead_xchacha20poly1305_ietf_keygen", sn_crypto_aead_xchacha20poly1305_ietf_keygen);
  V_FUNCTION("crypto_aead_xchacha20poly1305_ietf_encrypt", sn_crypto_aead_xchacha20poly1305_ietf_encrypt);
  V_FUNCTION("crypto_aead_xchacha20poly1305_ietf_decrypt", sn_crypto_aead_xchacha20poly1305_ietf_decrypt);
  V_FUNCTION("crypto_aead_xchacha20poly1305_ietf_encrypt_detached", sn_crypto_aead_xchacha20poly1305_ietf_encrypt_detached);
  V_FUNCTION("crypto_aead_xchacha20poly1305_ietf_decrypt_detached", sn_crypto_aead_xchacha20poly1305_ietf_decrypt_detached);
  V_UINT32("crypto_aead_xchacha20poly1305_ietf_ABYTES", crypto_aead_xchacha20poly1305_ietf_ABYTES);
  V_UINT32("crypto_aead_xchacha20poly1305_ietf_KEYBYTES", crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  V_UINT32("crypto_aead_xchacha20poly1305_ietf_NPUBBYTES", crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  V_UINT32("crypto_aead_xchacha20poly1305_ietf_NSECBYTES", crypto_aead_xchacha20poly1305_ietf_NSECBYTES);
  V_UINT64("crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX", crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX);

  V_FUNCTION("crypto_aead_chacha20poly1305_ietf_keygen", sn_crypto_aead_chacha20poly1305_ietf_keygen);
  V_FUNCTION("crypto_aead_chacha20poly1305_ietf_encrypt", sn_crypto_aead_chacha20poly1305_ietf_encrypt);
  V_FUNCTION("crypto_aead_chacha20poly1305_ietf_decrypt", sn_crypto_aead_chacha20poly1305_ietf_decrypt);
  V_FUNCTION("crypto_aead_chacha20poly1305_ietf_encrypt_detached", sn_crypto_aead_chacha20poly1305_ietf_encrypt_detached);
  V_FUNCTION("crypto_aead_chacha20poly1305_ietf_decrypt_detached", sn_crypto_aead_chacha20poly1305_ietf_decrypt_detached);
  V_UINT32("crypto_aead_chacha20poly1305_ietf_ABYTES", crypto_aead_chacha20poly1305_ietf_ABYTES);
  V_UINT32("crypto_aead_chacha20poly1305_ietf_KEYBYTES", crypto_aead_chacha20poly1305_ietf_KEYBYTES);
  V_UINT32("crypto_aead_chacha20poly1305_ietf_NPUBBYTES", crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  V_UINT32("crypto_aead_chacha20poly1305_ietf_NSECBYTES", crypto_aead_chacha20poly1305_ietf_NSECBYTES);
  V_UINT64("crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX", crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX);

  // crypto_auth

  V_FUNCTION("crypto_auth", sn_crypto_auth);
  V_FUNCTION("crypto_auth_verify", sn_crypto_auth_verify);
  V_UINT32("crypto_auth_BYTES", crypto_auth_BYTES);
  V_UINT32("crypto_auth_KEYBYTES", crypto_auth_KEYBYTES);
  V_STRING("crypto_auth_PRIMITIVE", crypto_auth_PRIMITIVE);

  // crypto_box

  V_FUNCTION("crypto_box_keypair", sn_crypto_box_keypair);
  V_FUNCTION("crypto_box_seed_keypair", sn_crypto_box_seed_keypair);
  V_FUNCTION("crypto_box_easy", sn_crypto_box_easy);
  V_FUNCTION("crypto_box_open_easy", sn_crypto_box_open_easy);
  V_FUNCTION("crypto_box_detached", sn_crypto_box_detached);
  V_FUNCTION("crypto_box_open_detached", sn_crypto_box_open_detached);
  V_FUNCTION("crypto_box_seal", sn_crypto_box_seal);
  V_FUNCTION_NOSCOPE("crypto_box_seal_open", sn_crypto_box_seal_open);

  V_UINT32("crypto_box_SEEDBYTES", crypto_box_SEEDBYTES);
  V_UINT32("crypto_box_PUBLICKEYBYTES", crypto_box_PUBLICKEYBYTES);
  V_UINT32("crypto_box_SECRETKEYBYTES", crypto_box_SECRETKEYBYTES);
  V_UINT32("crypto_box_NONCEBYTES", crypto_box_NONCEBYTES);
  V_UINT32("crypto_box_MACBYTES", crypto_box_MACBYTES);
  V_UINT32("crypto_box_SEALBYTES", crypto_box_SEALBYTES);
  V_STRING("crypto_box_PRIMITIVE", crypto_box_PRIMITIVE);

  // crypto_core

  V_FUNCTION("crypto_core_ed25519_is_valid_point", sn_crypto_core_ed25519_is_valid_point);
  V_FUNCTION("crypto_core_ed25519_from_uniform", sn_crypto_core_ed25519_from_uniform);
  V_FUNCTION("crypto_core_ed25519_add", sn_crypto_core_ed25519_add);
  V_FUNCTION("crypto_core_ed25519_sub", sn_crypto_core_ed25519_sub);
  V_FUNCTION("crypto_core_ed25519_scalar_random", sn_crypto_core_ed25519_scalar_random);
  V_FUNCTION("crypto_core_ed25519_scalar_reduce", sn_crypto_core_ed25519_scalar_reduce);
  V_FUNCTION("crypto_core_ed25519_scalar_invert", sn_crypto_core_ed25519_scalar_invert);
  V_FUNCTION("crypto_core_ed25519_scalar_negate", sn_crypto_core_ed25519_scalar_negate);
  V_FUNCTION("crypto_core_ed25519_scalar_complement", sn_crypto_core_ed25519_scalar_complement);
  V_FUNCTION("crypto_core_ed25519_scalar_add", sn_crypto_core_ed25519_scalar_add);
  V_FUNCTION("crypto_core_ed25519_scalar_sub", sn_crypto_core_ed25519_scalar_sub);
  V_UINT32("crypto_core_ed25519_BYTES", crypto_core_ed25519_BYTES);
  V_UINT32("crypto_core_ed25519_UNIFORMBYTES", crypto_core_ed25519_UNIFORMBYTES);
  V_UINT32("crypto_core_ed25519_SCALARBYTES", crypto_core_ed25519_SCALARBYTES);
  V_UINT32("crypto_core_ed25519_NONREDUCEDSCALARBYTES", crypto_core_ed25519_NONREDUCEDSCALARBYTES);

  // crypto_kdf

  V_FUNCTION("crypto_kdf_keygen", sn_crypto_kdf_keygen);
  V_FUNCTION("crypto_kdf_derive_from_key", sn_crypto_kdf_derive_from_key);
  V_UINT32("crypto_kdf_BYTES_MIN", crypto_kdf_BYTES_MIN);
  V_UINT32("crypto_kdf_BYTES_MAX", crypto_kdf_BYTES_MAX);
  V_UINT32("crypto_kdf_CONTEXTBYTES", crypto_kdf_CONTEXTBYTES);
  V_UINT32("crypto_kdf_KEYBYTES", crypto_kdf_KEYBYTES);
  V_STRING("crypto_kdf_PRIMITIVE", crypto_kdf_PRIMITIVE);

  // crypto_kx

  V_FUNCTION("crypto_kx_keypair", sn_crypto_kx_keypair);
  V_FUNCTION("crypto_kx_seed_keypair", sn_crypto_kx_seed_keypair);
  V_FUNCTION("crypto_kx_client_session_keys", sn_crypto_kx_client_session_keys);
  V_FUNCTION("crypto_kx_server_session_keys", sn_crypto_kx_server_session_keys);
  V_UINT32("crypto_kx_PUBLICKEYBYTES", crypto_kx_PUBLICKEYBYTES);
  V_UINT32("crypto_kx_SECRETKEYBYTES", crypto_kx_SECRETKEYBYTES);
  V_UINT32("crypto_kx_SEEDBYTES", crypto_kx_SEEDBYTES);
  V_UINT32("crypto_kx_SESSIONKEYBYTES", crypto_kx_SESSIONKEYBYTES);
  V_STRING("crypto_kx_PRIMITIVE", crypto_kx_PRIMITIVE);

  // crypto_generichash

  V_FUNCTION_NOSCOPE("crypto_generichash", sn_crypto_generichash);
  V_FUNCTION("crypto_generichash_batch", sn_crypto_generichash_batch);
  V_FUNCTION_NOSCOPE("crypto_generichash_batch", sn_crypto_generichash_batch);
  V_FUNCTION_NOSCOPE("crypto_generichash_keygen", sn_crypto_generichash_keygen);
  V_FUNCTION_NOSCOPE("crypto_generichash_init", sn_crypto_generichash_init);
  V_FUNCTION_NOSCOPE("crypto_generichash_update", sn_crypto_generichash_update);
  V_FUNCTION_NOSCOPE("crypto_generichash_final", sn_crypto_generichash_final);

  V_UINT32("crypto_generichash_STATEBYTES", sizeof(crypto_generichash_state));
  V_STRING("crypto_generichash_PRIMITIVE", crypto_generichash_PRIMITIVE);
  V_UINT32("crypto_generichash_BYTES_MIN", crypto_generichash_BYTES_MIN);
  V_UINT32("crypto_generichash_BYTES_MAX", crypto_generichash_BYTES_MAX);
  V_UINT32("crypto_generichash_BYTES", crypto_generichash_BYTES);
  V_UINT32("crypto_generichash_KEYBYTES_MIN", crypto_generichash_KEYBYTES_MIN);
  V_UINT32("crypto_generichash_KEYBYTES_MAX", crypto_generichash_KEYBYTES_MAX);
  V_UINT32("crypto_generichash_KEYBYTES", crypto_generichash_KEYBYTES);

  // crypto_hash

  V_FUNCTION("crypto_hash", sn_crypto_hash);
  V_UINT32("crypto_hash_BYTES", crypto_hash_BYTES);
  V_STRING("crypto_hash_PRIMITIVE", crypto_hash_PRIMITIVE);

  V_FUNCTION("crypto_hash_sha256", sn_crypto_hash_sha256);
  V_FUNCTION("crypto_hash_sha256_init", sn_crypto_hash_sha256_init);
  V_FUNCTION("crypto_hash_sha256_update", sn_crypto_hash_sha256_update);
  V_FUNCTION("crypto_hash_sha256_final", sn_crypto_hash_sha256_final);
  V_UINT32("crypto_hash_sha256_STATEBYTES", sizeof(crypto_hash_sha256_state));
  V_UINT32("crypto_hash_sha256_BYTES", crypto_hash_sha256_BYTES);

  V_FUNCTION("crypto_hash_sha512", sn_crypto_hash_sha512);
  V_FUNCTION("crypto_hash_sha512_init", sn_crypto_hash_sha512_init);
  V_FUNCTION("crypto_hash_sha512_update", sn_crypto_hash_sha512_update);
  V_FUNCTION("crypto_hash_sha512_final", sn_crypto_hash_sha512_final);
  V_UINT32("crypto_hash_sha512_STATEBYTES", sizeof(crypto_hash_sha512_state));
  V_UINT32("crypto_hash_sha512_BYTES", crypto_hash_sha512_BYTES);

  // crypto_onetimeauth

  V_FUNCTION("crypto_onetimeauth", sn_crypto_onetimeauth);
  V_FUNCTION("crypto_onetimeauth_verify", sn_crypto_onetimeauth_verify);
  V_FUNCTION("crypto_onetimeauth_init", sn_crypto_onetimeauth_init);
  V_FUNCTION("crypto_onetimeauth_update", sn_crypto_onetimeauth_update);
  V_FUNCTION("crypto_onetimeauth_final", sn_crypto_onetimeauth_final);
  V_UINT32("crypto_onetimeauth_STATEBYTES", sizeof(crypto_onetimeauth_state));
  V_UINT32("crypto_onetimeauth_BYTES", crypto_onetimeauth_BYTES);
  V_UINT32("crypto_onetimeauth_KEYBYTES", crypto_onetimeauth_KEYBYTES);
  V_STRING("crypto_onetimeauth_PRIMITIVE", crypto_onetimeauth_PRIMITIVE);

  // crypto_pwhash

  V_FUNCTION("crypto_pwhash", sn_crypto_pwhash);
  V_FUNCTION("crypto_pwhash_str", sn_crypto_pwhash_str);
  V_FUNCTION("crypto_pwhash_str_verify", sn_crypto_pwhash_str_verify);
  V_FUNCTION("crypto_pwhash_str_needs_rehash", sn_crypto_pwhash_str_needs_rehash);
  V_FUNCTION("crypto_pwhash_async", sn_crypto_pwhash_async);
  V_FUNCTION("crypto_pwhash_str_async", sn_crypto_pwhash_str_async);
  V_FUNCTION("crypto_pwhash_str_verify_async", sn_crypto_pwhash_str_verify_async);
  V_UINT32("crypto_pwhash_ALG_ARGON2I13", crypto_pwhash_ALG_ARGON2I13);
  V_UINT32("crypto_pwhash_ALG_ARGON2ID13", crypto_pwhash_ALG_ARGON2ID13);
  V_UINT32("crypto_pwhash_ALG_DEFAULT", crypto_pwhash_ALG_DEFAULT);
  V_UINT32("crypto_pwhash_BYTES_MIN", crypto_pwhash_BYTES_MIN);
  V_UINT32("crypto_pwhash_BYTES_MAX", crypto_pwhash_BYTES_MAX);
  V_UINT32("crypto_pwhash_PASSWD_MIN", crypto_pwhash_PASSWD_MIN);
  V_UINT32("crypto_pwhash_PASSWD_MAX", crypto_pwhash_PASSWD_MAX);
  V_UINT32("crypto_pwhash_SALTBYTES", crypto_pwhash_SALTBYTES);
  V_UINT32("crypto_pwhash_STRBYTES", crypto_pwhash_STRBYTES);
  V_STRING("crypto_pwhash_STRPREFIX", crypto_pwhash_STRPREFIX);
  V_UINT32("crypto_pwhash_OPSLIMIT_MIN", crypto_pwhash_OPSLIMIT_MIN);
  V_UINT32("crypto_pwhash_OPSLIMIT_MAX", crypto_pwhash_OPSLIMIT_MAX);
  V_UINT64("crypto_pwhash_MEMLIMIT_MIN", crypto_pwhash_MEMLIMIT_MIN);
  V_UINT64("crypto_pwhash_MEMLIMIT_MAX", crypto_pwhash_MEMLIMIT_MAX);
  V_UINT32("crypto_pwhash_OPSLIMIT_INTERACTIVE", crypto_pwhash_OPSLIMIT_INTERACTIVE);
  V_UINT64("crypto_pwhash_MEMLIMIT_INTERACTIVE", crypto_pwhash_MEMLIMIT_INTERACTIVE);
  V_UINT32("crypto_pwhash_OPSLIMIT_MODERATE", crypto_pwhash_OPSLIMIT_MODERATE);
  V_UINT64("crypto_pwhash_MEMLIMIT_MODERATE", crypto_pwhash_MEMLIMIT_MODERATE);
  V_UINT32("crypto_pwhash_OPSLIMIT_SENSITIVE", crypto_pwhash_OPSLIMIT_SENSITIVE);
  V_UINT64("crypto_pwhash_MEMLIMIT_SENSITIVE", crypto_pwhash_MEMLIMIT_SENSITIVE);
  V_STRING("crypto_pwhash_PRIMITIVE", crypto_pwhash_PRIMITIVE);

  V_FUNCTION("crypto_pwhash_scryptsalsa208sha256", sn_crypto_pwhash_scryptsalsa208sha256);
  V_FUNCTION("crypto_pwhash_scryptsalsa208sha256_str", sn_crypto_pwhash_scryptsalsa208sha256_str);
  V_FUNCTION("crypto_pwhash_scryptsalsa208sha256_str_verify", sn_crypto_pwhash_scryptsalsa208sha256_str_verify);
  V_FUNCTION("crypto_pwhash_scryptsalsa208sha256_str_needs_rehash", sn_crypto_pwhash_scryptsalsa208sha256_str_needs_rehash);
  V_FUNCTION("crypto_pwhash_scryptsalsa208sha256_async", sn_crypto_pwhash_scryptsalsa208sha256_async);
  V_FUNCTION("crypto_pwhash_scryptsalsa208sha256_str_async", sn_crypto_pwhash_scryptsalsa208sha256_str_async)
  V_FUNCTION("crypto_pwhash_scryptsalsa208sha256_str_verify_async", sn_crypto_pwhash_scryptsalsa208sha256_str_verify_async);
  V_UINT64("crypto_pwhash_scryptsalsa208sha256_BYTES_MIN", crypto_pwhash_scryptsalsa208sha256_BYTES_MIN);
  V_UINT64("crypto_pwhash_scryptsalsa208sha256_BYTES_MAX", crypto_pwhash_scryptsalsa208sha256_BYTES_MAX);
  V_UINT64("crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN", crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN);
  V_UINT64("crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX", crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX);
  V_UINT64("crypto_pwhash_scryptsalsa208sha256_SALTBYTES", crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
  V_UINT64("crypto_pwhash_scryptsalsa208sha256_STRBYTES", crypto_pwhash_scryptsalsa208sha256_STRBYTES);
  V_STRING("crypto_pwhash_scryptsalsa208sha256_STRPREFIX", crypto_pwhash_scryptsalsa208sha256_STRPREFIX);
  V_UINT32("crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN", crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN);
  V_UINT32("crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX", crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX);
  V_UINT64("crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN", crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN);
  V_UINT64("crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX", crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX);
  V_UINT32("crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE", crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE);
  V_UINT64("crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE", crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
  V_UINT32("crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE", crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE);
  V_UINT64("crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE", crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE);

  // crypto_scalarmult

  V_FUNCTION("crypto_scalarmult_base", sn_crypto_scalarmult_base);
  V_FUNCTION("crypto_scalarmult", sn_crypto_scalarmult);
  V_STRING("crypto_scalarmult_PRIMITIVE", crypto_scalarmult_PRIMITIVE);
  V_UINT32("crypto_scalarmult_BYTES", crypto_scalarmult_BYTES);
  V_UINT32("crypto_scalarmult_SCALARBYTES", crypto_scalarmult_SCALARBYTES);

  V_FUNCTION("crypto_scalarmult_ed25519_base", sn_crypto_scalarmult_ed25519_base);
  V_FUNCTION("crypto_scalarmult_ed25519", sn_crypto_scalarmult_ed25519);
  V_FUNCTION("crypto_scalarmult_ed25519_base_noclamp", sn_crypto_scalarmult_ed25519_base_noclamp);
  V_FUNCTION("crypto_scalarmult_ed25519_noclamp", sn_crypto_scalarmult_ed25519_noclamp);
  V_UINT32("crypto_scalarmult_ed25519_BYTES", crypto_scalarmult_ed25519_BYTES);
  V_UINT32("crypto_scalarmult_ed25519_SCALARBYTES", crypto_scalarmult_ed25519_SCALARBYTES);

  // crypto_secretbox

  V_FUNCTION("crypto_secretbox_easy", sn_crypto_secretbox_easy);
  V_FUNCTION("crypto_secretbox_open_easy", sn_crypto_secretbox_open_easy);
  V_FUNCTION("crypto_secretbox_detached", sn_crypto_secretbox_detached);
  V_FUNCTION("crypto_secretbox_open_detached", sn_crypto_secretbox_open_detached);
  V_UINT32("crypto_secretbox_KEYBYTES", crypto_secretbox_KEYBYTES);
  V_UINT32("crypto_secretbox_NONCEBYTES", crypto_secretbox_NONCEBYTES);
  V_UINT32("crypto_secretbox_MACBYTES", crypto_secretbox_MACBYTES);
  V_STRING("crypto_secretbox_PRIMITIVE", crypto_secretbox_PRIMITIVE);

  // crypto_secretstream

  V_FUNCTION_NOSCOPE("crypto_secretstream_xchacha20poly1305_keygen", sn_crypto_secretstream_xchacha20poly1305_keygen);
  V_FUNCTION_NOSCOPE("crypto_secretstream_xchacha20poly1305_init_push", sn_crypto_secretstream_xchacha20poly1305_init_push);
  V_FUNCTION_NOSCOPE("crypto_secretstream_xchacha20poly1305_init_pull", sn_crypto_secretstream_xchacha20poly1305_init_pull);
  V_FUNCTION_NOSCOPE("crypto_secretstream_xchacha20poly1305_push", sn_crypto_secretstream_xchacha20poly1305_push);
  V_FUNCTION_NOSCOPE("crypto_secretstream_xchacha20poly1305_pull", sn_crypto_secretstream_xchacha20poly1305_pull);
  V_FUNCTION_NOSCOPE("crypto_secretstream_xchacha20poly1305_rekey", sn_crypto_secretstream_xchacha20poly1305_rekey);

  V_UINT32("crypto_secretstream_xchacha20poly1305_STATEBYTES", sizeof(crypto_secretstream_xchacha20poly1305_state));
  V_UINT32("crypto_secretstream_xchacha20poly1305_ABYTES", crypto_secretstream_xchacha20poly1305_ABYTES);
  V_UINT32("crypto_secretstream_xchacha20poly1305_HEADERBYTES", crypto_secretstream_xchacha20poly1305_HEADERBYTES);
  V_UINT32("crypto_secretstream_xchacha20poly1305_KEYBYTES", crypto_secretstream_xchacha20poly1305_KEYBYTES);
  V_UINT32("crypto_secretstream_xchacha20poly1305_TAGBYTES", 1);
  V_UINT64("crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX", crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX);
  V_UINT32("crypto_secretstream_xchacha20poly1305_TAG_MESSAGE", crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
  V_UINT32("crypto_secretstream_xchacha20poly1305_TAG_PUSH", crypto_secretstream_xchacha20poly1305_TAG_PUSH);
  V_UINT32("crypto_secretstream_xchacha20poly1305_TAG_REKEY", crypto_secretstream_xchacha20poly1305_TAG_REKEY);
  V_UINT32("crypto_secretstream_xchacha20poly1305_TAG_FINAL", crypto_secretstream_xchacha20poly1305_TAG_FINAL);

  // crypto_shorthash

  V_FUNCTION("crypto_shorthash", sn_crypto_shorthash);
  V_UINT32("crypto_shorthash_BYTES", crypto_shorthash_BYTES);
  V_UINT32("crypto_shorthash_KEYBYTES", crypto_shorthash_KEYBYTES);
  V_STRING("crypto_shorthash_PRIMITIVE", crypto_shorthash_PRIMITIVE);

  // crypto_sign

  V_FUNCTION("crypto_sign_keypair", sn_crypto_sign_keypair);
  V_FUNCTION("crypto_sign_seed_keypair", sn_crypto_sign_seed_keypair);
  V_FUNCTION("crypto_sign", sn_crypto_sign);
  V_FUNCTION("crypto_sign_open", sn_crypto_sign_open);
  V_FUNCTION("crypto_sign_detached", sn_crypto_sign_detached);
  V_FUNCTION_NOSCOPE("crypto_sign_verify_detached", sn_crypto_sign_verify_detached);
  V_FUNCTION("crypto_sign_ed25519_sk_to_pk", sn_crypto_sign_ed25519_sk_to_pk);
  V_FUNCTION("crypto_sign_ed25519_pk_to_curve25519", sn_crypto_sign_ed25519_pk_to_curve25519);
  V_FUNCTION("crypto_sign_ed25519_sk_to_curve25519", sn_crypto_sign_ed25519_sk_to_curve25519);

  V_UINT32("crypto_sign_SEEDBYTES", crypto_sign_SEEDBYTES);
  V_UINT32("crypto_sign_PUBLICKEYBYTES", crypto_sign_PUBLICKEYBYTES);
  V_UINT32("crypto_sign_SECRETKEYBYTES", crypto_sign_SECRETKEYBYTES);
  V_UINT32("crypto_sign_BYTES", crypto_sign_BYTES);

  // crypto_stream

  V_FUNCTION("crypto_stream", sn_crypto_stream);
  V_UINT32("crypto_stream_KEYBYTES", crypto_stream_KEYBYTES);
  V_UINT32("crypto_stream_NONCEBYTES", crypto_stream_NONCEBYTES);
  V_STRING("crypto_stream_PRIMITIVE", crypto_stream_PRIMITIVE);

  V_FUNCTION_NOSCOPE("crypto_stream_xor", sn_crypto_stream_xor);
  V_FUNCTION("crypto_stream_xor_init", sn_crypto_stream_xor_wrap_init);
  V_FUNCTION("crypto_stream_xor_update", sn_crypto_stream_xor_wrap_update);
  V_FUNCTION("crypto_stream_xor_final", sn_crypto_stream_xor_wrap_final);
  V_UINT32("crypto_stream_xor_STATEBYTES", sizeof(sn_crypto_stream_xor_state));

  V_FUNCTION("crypto_stream_chacha20", sn_crypto_stream_chacha20);
  V_UINT32("crypto_stream_chacha20_KEYBYTES", crypto_stream_chacha20_KEYBYTES);
  V_UINT32("crypto_stream_chacha20_NONCEBYTES", crypto_stream_chacha20_NONCEBYTES);
  V_UINT64("crypto_stream_chacha20_MESSAGEBYTES_MAX", crypto_stream_chacha20_MESSAGEBYTES_MAX);

  V_FUNCTION("crypto_stream_chacha20_xor", sn_crypto_stream_chacha20_xor);
  V_FUNCTION("crypto_stream_chacha20_xor_ic", sn_crypto_stream_chacha20_xor_ic);
  V_FUNCTION("crypto_stream_chacha20_xor_init", sn_crypto_stream_chacha20_xor_wrap_init);
  V_FUNCTION("crypto_stream_chacha20_xor_update", sn_crypto_stream_chacha20_xor_wrap_update);
  V_FUNCTION("crypto_stream_chacha20_xor_final", sn_crypto_stream_chacha20_xor_wrap_final);
  V_UINT32("crypto_stream_chacha20_xor_STATEBYTES", sizeof(sn_crypto_stream_chacha20_xor_state));

  V_FUNCTION("crypto_stream_chacha20_ietf", sn_crypto_stream_chacha20_ietf);
  V_UINT32("crypto_stream_chacha20_ietf_KEYBYTES", crypto_stream_chacha20_ietf_KEYBYTES);
  V_UINT32("crypto_stream_chacha20_ietf_NONCEBYTES", crypto_stream_chacha20_ietf_NONCEBYTES);
  V_UINT64("crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX", crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX);
  V_UINT32("crypto_stream_chacha20_ietf_xor_STATEBYTES", sizeof(sn_crypto_stream_chacha20_ietf_xor_state));

  V_FUNCTION("crypto_stream_chacha20_ietf_xor", sn_crypto_stream_chacha20_ietf_xor);
  V_FUNCTION("crypto_stream_chacha20_ietf_xor_ic", sn_crypto_stream_chacha20_ietf_xor_ic);
  V_FUNCTION("crypto_stream_chacha20_ietf_xor_init", sn_crypto_stream_chacha20_ietf_xor_wrap_init);
  V_FUNCTION("crypto_stream_chacha20_ietf_xor_update", sn_crypto_stream_chacha20_ietf_xor_wrap_update);
  V_FUNCTION("crypto_stream_chacha20_ietf_xor_final", sn_crypto_stream_chacha20_ietf_xor_wrap_final);

  V_FUNCTION("crypto_stream_xchacha20", sn_crypto_stream_xchacha20);
  V_UINT32("crypto_stream_xchacha20_KEYBYTES", crypto_stream_xchacha20_KEYBYTES);
  V_UINT32("crypto_stream_xchacha20_NONCEBYTES", crypto_stream_xchacha20_NONCEBYTES);
  V_UINT64("crypto_stream_xchacha20_MESSAGEBYTES_MAX", crypto_stream_xchacha20_MESSAGEBYTES_MAX);

  V_FUNCTION("crypto_stream_xchacha20_xor", sn_crypto_stream_xchacha20_xor);
  V_FUNCTION("crypto_stream_xchacha20_xor_ic", sn_crypto_stream_xchacha20_xor_ic);
  V_FUNCTION("crypto_stream_xchacha20_xor_init", sn_crypto_stream_xchacha20_xor_wrap_init);
  V_FUNCTION("crypto_stream_xchacha20_xor_update", sn_crypto_stream_xchacha20_xor_wrap_update);
  V_FUNCTION("crypto_stream_xchacha20_xor_final", sn_crypto_stream_xchacha20_xor_wrap_final);
  V_FUNCTION("crypto_stream_xchacha20", sn_crypto_stream_xchacha20);
  V_UINT32("crypto_stream_xchacha20_xor_STATEBYTES", sizeof(sn_crypto_stream_xchacha20_xor_state));

  V_FUNCTION("crypto_stream_salsa20", sn_crypto_stream_salsa20);
  V_UINT32("crypto_stream_salsa20_KEYBYTES", crypto_stream_salsa20_KEYBYTES);
  V_UINT32("crypto_stream_salsa20_NONCEBYTES", crypto_stream_salsa20_NONCEBYTES);
  V_UINT64("crypto_stream_salsa20_MESSAGEBYTES_MAX", crypto_stream_salsa20_MESSAGEBYTES_MAX);

  V_FUNCTION("crypto_stream_salsa20_xor", sn_crypto_stream_salsa20_xor);
  V_FUNCTION("crypto_stream_salsa20_xor_ic", sn_crypto_stream_salsa20_xor_ic);
  V_FUNCTION("crypto_stream_salsa20_xor_init", sn_crypto_stream_salsa20_xor_wrap_init);
  V_FUNCTION("crypto_stream_salsa20_xor_update", sn_crypto_stream_salsa20_xor_wrap_update);
  V_FUNCTION("crypto_stream_salsa20_xor_final", sn_crypto_stream_salsa20_xor_wrap_final);
  V_UINT32("crypto_stream_salsa20_xor_STATEBYTES", sizeof(sn_crypto_stream_salsa20_xor_state));

  // extensions

  // tweak

  V_FUNCTION("extension_tweak_ed25519_base", sn_extension_tweak_ed25519_base);
  V_FUNCTION("extension_tweak_ed25519_sign_detached", sn_extension_tweak_ed25519_sign_detached);
  V_FUNCTION("extension_tweak_ed25519_sk_to_scalar", sn_extension_tweak_ed25519_sk_to_scalar);
  V_FUNCTION("extension_tweak_ed25519_scalar", sn_extension_tweak_ed25519_scalar);
  V_FUNCTION("extension_tweak_ed25519_pk", sn_extension_tweak_ed25519_pk);
  V_FUNCTION("extension_tweak_ed25519_keypair", sn_extension_tweak_ed25519_keypair);
  V_FUNCTION("extension_tweak_ed25519_scalar_add", sn_extension_tweak_ed25519_scalar_add);
  V_FUNCTION("extension_tweak_ed25519_pk_add", sn_extension_tweak_ed25519_pk_add);
  V_FUNCTION("extension_tweak_ed25519_keypair_add", sn_extension_tweak_ed25519_keypair_add);
  V_UINT32("extension_tweak_ed25519_BYTES", sn__extension_tweak_ed25519_BYTES);
  V_UINT32("extension_tweak_ed25519_SCALARBYTES", sn__extension_tweak_ed25519_SCALARBYTES);

  // pbkdf2

  V_FUNCTION("extension_pbkdf2_sha512", sn_extension_pbkdf2_sha512);
  V_FUNCTION("extension_pbkdf2_sha512_async", sn_extension_pbkdf2_sha512_async);
  V_UINT32("extension_pbkdf2_sha512_SALTBYTES", sn__extension_pbkdf2_sha512_SALTBYTES);
  V_UINT32("extension_pbkdf2_sha512_HASHBYTES", sn__extension_pbkdf2_sha512_HASHBYTES);
  V_UINT32("extension_pbkdf2_sha512_ITERATIONS_MIN", sn__extension_pbkdf2_sha512_ITERATIONS_MIN);
  V_UINT64("extension_pbkdf2_sha512_BYTES_MAX", sn__extension_pbkdf2_sha512_BYTES_MAX);

#undef V_FUNCTION
#undef V_FUNCTION_NOSCOPE
#undef V_UINT32
#undef V_UINT64
#undef V_STRING

  return exports;
}

BARE_MODULE(sodium_native, sodium_native_exports)
