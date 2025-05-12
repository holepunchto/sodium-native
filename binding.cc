#include <assert.h>
#include <bare.h>
#include <js.h>
#include <jstl.h>
#include <stdbool.h>
#include <stdint.h>
#include <uv.h>
#include <string.h>
#include <sodium.h>
#include "macros.h"

#include "extensions/tweak/tweak.h"
#include "extensions/pbkdf2/pbkdf2.h"
#include "sodium/crypto_generichash.h"

static uint8_t typedarray_width (js_typedarray_type_t type) {
  switch (type) {
    case js_int8array: return 1;
    case js_uint8array: return 1;
    case js_uint8clampedarray: return 1;
    case js_int16array: return 2;
    case js_uint16array: return 2;
    case js_int32array: return 4;
    case js_uint32array: return 4;
    case js_float32array: return 4;
    case js_float64array: return 8;
    case js_bigint64array: return 8;
    case js_biguint64array: return 8;
    default: return 0;
  }
}

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
sn_external_arraybuffer_finalize (js_env_t *env, void *finalise_data, void *finalise_hint) {
  sodium_free(finalise_data);
}

static js_arraybuffer_t
sn_sodium_malloc (js_env_t *env, js_receiver_t, uint32_t len) {
  void *ptr = sodium_malloc(len);
  assert(ptr != nullptr);

  js_value_t *buffer;
  int err = js_create_external_arraybuffer(env, ptr, len, sn_external_arraybuffer_finalize, NULL, &buffer);
  assert(err == 0);

  return static_cast<js_arraybuffer_t>(buffer);
}

static void
sn_sodium_free (js_env_t *env, js_receiver_t, js_arraybuffer_t buf) {
  int err;

  js_value_t * handle = static_cast<js_value_t *>(buf);

  bool is_detached;
  err = js_is_detached_arraybuffer(env, handle, &is_detached);
  assert(err == 0);

  std::span<uint8_t> view;
  err = js_get_arraybuffer_info(env, buf, view);
  assert(err == 0);

  if (is_detached || view.data() == nullptr) return;

  err = js_detach_arraybuffer(env, handle);
  assert(err == 0);
}

static inline int
sn_sodium_mprotect_noaccess (js_env_t *env, js_receiver_t, js_arraybuffer_t buf) {
  std::span<uint8_t> view;

  int err = js_get_arraybuffer_info(env, buf, view);
  assert(err == 0);

  return sodium_mprotect_noaccess(view.data());
}


static inline int
sn_sodium_mprotect_readonly (js_env_t *env, js_receiver_t, js_arraybuffer_t buf) {
  std::span<uint8_t> view;

  int err = js_get_arraybuffer_info(env, buf, view);
  assert(err == 0);

  return sodium_mprotect_readonly(view.data());
}


static inline int
sn_sodium_mprotect_readwrite (js_env_t *env, js_receiver_t, js_arraybuffer_t buf) {
  std::span<uint8_t> view;

  int err = js_get_arraybuffer_info(env, buf, view);
  assert(err == 0);

  return sodium_mprotect_readwrite(view.data());
}

static inline uint32_t // TODO: test envless
sn_randombytes_random (js_env_t *env, js_receiver_t) {
  return randombytes_random();
}

static inline uint32_t // TODO: test envless
sn_randombytes_uniform (js_env_t *env, js_receiver_t, uint32_t upper_bound) {
  return randombytes_uniform(upper_bound);
}

static inline void
sn_randombytes_buf (
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
sn_randombytes_buf_deterministic (
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
sn_sodium_pad (js_env_t *, js_receiver_t, js_typedarray_span_t<> buf, uint32_t unpadded_buflen, uint32_t blocksize) {
  size_t padded_buflen;

  sodium_pad(&padded_buflen, buf.data(), unpadded_buflen, blocksize, buf.size_bytes());

  return padded_buflen;
}

static inline uint32_t
sn_sodium_unpad (js_env_t *, js_receiver_t, js_typedarray_span_t<> buf, uint32_t padded_buflen, uint32_t blocksize) {
  size_t unpadded_buflen;

  sodium_unpad(&unpadded_buflen, buf.data(), padded_buflen, blocksize);

  return unpadded_buflen;
}

static inline int
sn_crypto_sign_keypair (js_env_t *, js_receiver_t, js_typedarray_span_t<> pk, js_typedarray_span_t<> sk) {
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
sn_crypto_sign_verify_detached (
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
sn_crypto_generichash (
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_span_t out,
  uint32_t out_offset,
  uint32_t out_len,

  js_arraybuffer_span_t in,
  uint32_t in_offset,
  uint32_t in_len,

  js_object_t key,
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
    uint8_t *slab;
    size_t slab_len;

    int err = js_get_arraybuffer_info(env, static_cast<js_arraybuffer_t &>(key), slab, slab_len);
    assert(err == 0);

    assert(key_len + key_offset <= slab_len);
    key_data = slab + key_offset;

    assert(
      key_len >= crypto_generichash_KEYBYTES_MIN &&
      key_len <= crypto_generichash_KEYBYTES_MAX
    );
  }

  return crypto_generichash(&out[out_offset], out_len, &in[in_offset], in_len, key_data, key_len);
}

static inline int
sn_crypto_generichash_batch(
    js_env_t *env,
    js_receiver_t,
    js_typedarray_t<uint8_t> out,
    std::vector<js_typedarray_t<uint8_t>> batch,
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
    bool is_typedarray = false;

    int err = js_is_typedarray(env, static_cast<js_handle_t &>(buf), is_typedarray);
    assert(err == 0);

    std::span<uint8_t> view;
    err = js_get_typedarray_info<uint8_t>(env, buf, view);
    assert(err == 0);

    err = crypto_generichash_update(&state, view.data(), view.size());
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
sn_crypto_generichash_init (
  js_env_t *env,
  js_receiver_t,

  js_arraybuffer_span_t state,
  uint32_t state_offset,
  uint32_t state_len,

  js_object_t key,
  uint32_t key_offset,
  uint32_t key_len,

  uint32_t out_len
) {
  assert_bounds(state);
  assert(state_len == sizeof(crypto_generichash_state));

  uint8_t *key_data = NULL;
  if (key_len) {
    uint8_t *slab;
    size_t slab_len;

    int err = js_get_arraybuffer_info(env, static_cast<js_arraybuffer_t &>(key), slab, slab_len);
    assert(err == 0);

    assert(key_len + key_offset <= slab_len);
    key_data = slab + key_offset;

    assert(
      key_len >= crypto_generichash_KEYBYTES_MIN &&
      key_len <= crypto_generichash_KEYBYTES_MAX
    );
  }

  auto state_data = reinterpret_cast<crypto_generichash_state *>(&state[state_offset]);

  return crypto_generichash_init(state_data, key_data, key_len, out_len);
}

static inline int
sn_crypto_generichash_update (
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
sn_crypto_generichash_final (
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
sn_crypto_box_keypair (js_env_t *, js_receiver_t, js_typedarray_span_t<> pk, js_typedarray_span_t<> sk) {
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
sn_crypto_box_easy (
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
sn_crypto_box_open_easy (
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
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> k
) {
  assert(state.size_bytes() == sizeof(crypto_onetimeauth_state));
  auto state_data = reinterpret_cast<crypto_onetimeauth_state *>(state.data());

  assert(k.size_bytes() == crypto_onetimeauth_KEYBYTES);

  return crypto_onetimeauth_init(state_data, k.data());
}

static inline int
sn_crypto_onetimeauth_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> in
) {
  assert(state.size_bytes() == sizeof(crypto_onetimeauth_state));
  auto state_data = reinterpret_cast<crypto_onetimeauth_state *>(state.data());

  return crypto_onetimeauth_update(state_data, in.data(), in.size_bytes());
}

static inline int
sn_crypto_onetimeauth_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> out
) {
  assert(state.size_bytes() == sizeof(crypto_onetimeauth_state));
  auto state_data = reinterpret_cast<crypto_onetimeauth_state *>(state.data());

  assert(out.size_bytes() == crypto_onetimeauth_BYTES);

  return crypto_onetimeauth_final(state_data, out.data());
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
  js_typedarray_span_t<> passwd,
  js_typedarray_span_t<> salt,
  int64_t opslimit,
  int64_t memlimit,
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
    reinterpret_cast<const char *>(passwd.data()),
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
  js_typedarray_span_t<> out,
  js_typedarray_span_t<> passwd,
int64_t opslimit,
  int64_t memlimit
) {
  assert(out.size_bytes() == crypto_pwhash_STRBYTES);
  assert(opslimit >= crypto_pwhash_OPSLIMIT_MIN);
  assert(opslimit <= crypto_pwhash_OPSLIMIT_MAX);
  assert(memlimit >= crypto_pwhash_MEMLIMIT_MIN);
  assert(memlimit <= crypto_pwhash_MEMLIMIT_MAX);

  return crypto_pwhash_str(
    reinterpret_cast<char *>(out.data()),
    reinterpret_cast<const char *>(passwd.data()),
    passwd.size_bytes(),
    opslimit,
    memlimit
  );
}

static inline bool
sn_crypto_pwhash_str_verify(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> str,
  js_typedarray_span_t<> passwd
) {
  assert(str.size_bytes() == crypto_pwhash_STRBYTES);

  int res = crypto_pwhash_str_verify(
    reinterpret_cast<const char *>(str.data()),
    reinterpret_cast<const char *>(passwd.data()),
    passwd.size_bytes()
  );

  return res == 0;
}

// CHECK: returns 1, 0, -1
static inline bool
sn_crypto_pwhash_str_needs_rehash(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> str,
  int64_t opslimit,
  int64_t memlimit
) {
  assert(str.size_bytes() == crypto_pwhash_STRBYTES);
  assert(opslimit >= crypto_pwhash_OPSLIMIT_MIN);
  assert(opslimit <= crypto_pwhash_OPSLIMIT_MAX);
  assert(memlimit >= crypto_pwhash_MEMLIMIT_MIN);
  assert(memlimit <= static_cast<int64_t>(crypto_pwhash_MEMLIMIT_MAX));

  int res = crypto_pwhash_str_needs_rehash(
    reinterpret_cast<const char *>(str.data()),
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
  js_typedarray_span_t<> passwd,
  js_typedarray_span_t<> salt,
  int64_t opslimit,
  int64_t memlimit
) {
  assert(out.size_bytes() >= crypto_pwhash_scryptsalsa208sha256_BYTES_MIN);
  assert(out.size_bytes() <= crypto_pwhash_scryptsalsa208sha256_BYTES_MAX);
  assert(salt.size_bytes() == crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
  assert(opslimit >= crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN);
  assert(opslimit <= crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX);
  assert(memlimit >= crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN);
  assert(memlimit <= static_cast<int64_t>(crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX));

  return crypto_pwhash_scryptsalsa208sha256(
    out.data(),
    out.size_bytes(),
    reinterpret_cast<const char *>(passwd.data()),
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
  js_typedarray_span_t<> out,
  js_typedarray_span_t<> passwd,
  int64_t opslimit,
  int64_t memlimit
) {
  assert(out.size_bytes() == crypto_pwhash_scryptsalsa208sha256_STRBYTES);
  assert(opslimit >= crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN);
  assert(opslimit <= crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX);
  assert(memlimit >= crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN);
  assert(memlimit <= static_cast<int64_t>(crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX));

  return crypto_pwhash_scryptsalsa208sha256_str(
    reinterpret_cast<char *>(out.data()),
    reinterpret_cast<const char *>(passwd.data()),
    passwd.size_bytes(),
    opslimit,
    memlimit
  );
}

static inline bool
sn_crypto_pwhash_scryptsalsa208sha256_str_verify(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> str,
  js_typedarray_span_t<> passwd
) {
  assert(str.size_bytes() == crypto_pwhash_scryptsalsa208sha256_STRBYTES);

  int res = crypto_pwhash_scryptsalsa208sha256_str_verify(
    reinterpret_cast<const char *>(str.data()),
    reinterpret_cast<const char *>(passwd.data()),
    passwd.size_bytes()
  );

  return res == 0;
}

static inline bool
sn_crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> str,
  int64_t opslimit,
  int64_t memlimit
) {
  assert(str.size_bytes() == crypto_pwhash_scryptsalsa208sha256_STRBYTES);
  assert(opslimit >= crypto_pwhash_OPSLIMIT_MIN);
  assert(opslimit <= crypto_pwhash_OPSLIMIT_MAX);
  assert(memlimit >= crypto_pwhash_MEMLIMIT_MIN);
  assert(memlimit <= static_cast<int64_t>(crypto_pwhash_MEMLIMIT_MAX));

  int res = crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(
    reinterpret_cast<const char *>(str.data()),
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
  int64_t subkey_id,
  js_typedarray_span_t<> ctx,
  js_typedarray_span_t<> key
) {
  assert(subkey.size_bytes() >= crypto_kdf_BYTES_MIN);
  assert(subkey.size_bytes() <= crypto_kdf_BYTES_MAX);
  assert(ctx.size_bytes() == crypto_kdf_CONTEXTBYTES);
  assert(key.size_bytes() == crypto_kdf_KEYBYTES);

  return crypto_kdf_derive_from_key(
    subkey.data(),
    subkey.size_bytes(),
    static_cast<uint64_t>(subkey_id),
    reinterpret_cast<const char *>(ctx.data()),
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
  js_typedarray_span_t<> state
) {
  assert(state.size_bytes() == sizeof(crypto_hash_sha256_state));
  auto state_data = reinterpret_cast<crypto_hash_sha256_state *>(state.data());

  return crypto_hash_sha256_init(state_data);
}

static inline int
sn_crypto_hash_sha256_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> in
) {
  assert(state.size_bytes() == sizeof(crypto_hash_sha256_state));
  auto state_data = reinterpret_cast<crypto_hash_sha256_state *>(state.data());

  return crypto_hash_sha256_update(state_data, in.data(), in.size_bytes());
}

static inline int
sn_crypto_hash_sha256_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> out
) {
  assert(state.size_bytes() == sizeof(crypto_hash_sha256_state));
  auto state_data = reinterpret_cast<crypto_hash_sha256_state *>(state.data());

  assert(out.size_bytes() == crypto_hash_sha256_BYTES);

  return crypto_hash_sha256_final(state_data, out.data());
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
  js_typedarray_span_t<> state
) {
  assert(state.size_bytes() == sizeof(crypto_hash_sha512_state));
  auto state_data = reinterpret_cast<crypto_hash_sha512_state *>(state.data());

  return crypto_hash_sha512_init(state_data);
}

static inline int
sn_crypto_hash_sha512_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> in
) {
  assert(state.size_bytes() == sizeof(crypto_hash_sha512_state));
  auto state_data = reinterpret_cast<crypto_hash_sha512_state *>(state.data());

  return crypto_hash_sha512_update(state_data, in.data(), in.size_bytes());
}

static inline int
sn_crypto_hash_sha512_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> out
) {
  assert(state.size_bytes() == sizeof(crypto_hash_sha512_state));
  auto state_data = reinterpret_cast<crypto_hash_sha512_state *>(state.data());

  assert(out.size_bytes() == crypto_hash_sha512_BYTES);

  return crypto_hash_sha512_final(state_data, out.data());
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

static inline int64_t
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

  return static_cast<int64_t>(clen);
}

static inline int64_t
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

  return static_cast<int64_t>(mlen);
}

static inline int64_t
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

  return static_cast<int64_t>(maclen);
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

static inline int64_t
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

  return static_cast<int64_t>(clen);
}

static inline int64_t
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

  return static_cast<int64_t>(mlen);
}

static inline int64_t
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

  return static_cast<int64_t>(maclen);
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
sn_crypto_secretstream_xchacha20poly1305_keygen (
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
sn_crypto_secretstream_xchacha20poly1305_init_push (
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

static inline int64_t
sn_crypto_secretstream_xchacha20poly1305_push (
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

  js_object_t ad,
  uint32_t ad_offset,
  uint32_t ad_len,

  uint32_t tag
) {
  assert_bounds(state);
  assert_bounds(c);
  assert_bounds(m);

  assert(state_len == sizeof(crypto_secretstream_xchacha20poly1305_state));
  auto state_data = reinterpret_cast<crypto_secretstream_xchacha20poly1305_state *>(&state[state_offset]);

  // next-line kept for future rewrites
  // assert(m_len <= crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX);
  assert(c_len == m_len + crypto_secretstream_xchacha20poly1305_ABYTES);
  assert(c_len <= 0xffffffff && "32bit integer");

  uint8_t *ad_data = NULL;
  if (ad_len) {
    uint8_t *slab;
    size_t slab_len;

    int err = js_get_arraybuffer_info(env, static_cast<js_arraybuffer_t &>(ad), slab, slab_len);
    assert(err == 0);

    assert(ad_len + ad_offset <= slab_len);
    ad_data = slab + ad_offset;
  }

  unsigned long long clen = 0;

  int res = crypto_secretstream_xchacha20poly1305_push(state_data, &c[c_offset], &clen, &m[m_offset], m_len, ad_data, ad_len, tag);
  if (res < 0) return -1;

  return clen;
}

static inline int
sn_crypto_secretstream_xchacha20poly1305_init_pull (
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


static inline int64_t
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

  js_object_t ad,
  uint32_t ad_offset,
  uint32_t ad_len
) {
  assert_bounds(state);
  assert_bounds(m);
  assert_bounds(tag);
  assert_bounds(c);

  assert(state_len == sizeof(crypto_secretstream_xchacha20poly1305_state));
  auto state_data = reinterpret_cast<crypto_secretstream_xchacha20poly1305_state*>(&state[state_offset]);

  assert(c_len >= crypto_secretstream_xchacha20poly1305_ABYTES);
  assert(tag_len == 1);
  assert(m_len == c_len - crypto_secretstream_xchacha20poly1305_ABYTES);
  assert(m_len <= 0xffffffff);

  uint8_t *ad_data = NULL;
  if (ad_len) {
    uint8_t *slab;
    size_t slab_len;

    int err = js_get_arraybuffer_info(env, static_cast<js_arraybuffer_t &>(ad), slab, slab_len);
    assert(err == 0);

    assert(ad_len + ad_offset <= slab_len);
    ad_data = slab + ad_offset;
  }

  unsigned long long mlen = 0;

  int res = crypto_secretstream_xchacha20poly1305_pull(state_data, &m[m_offset], &mlen, &tag[tag_offset], &c[c_offset], c_len, ad_data, ad_len);
  if (res < 0) return -1;

  return mlen;
}

static inline void
sn_crypto_secretstream_xchacha20poly1305_rekey (
  js_env_t *,
  js_receiver_t,

  js_arraybuffer_span_t state,
  uint32_t state_offset,
  uint32_t state_len
) {
  assert_bounds(state);

  assert(state_len == sizeof(crypto_secretstream_xchacha20poly1305_state));
  auto state_data = reinterpret_cast<crypto_secretstream_xchacha20poly1305_state*>(&state[state_offset]);

  crypto_secretstream_xchacha20poly1305_rekey(state_data);
}

typedef struct sn_async_task_t {
  uv_work_t task;

  enum {
    sn_async_task_promise,
    sn_async_task_callback
  } type;

  void *req;
  int code;

  js_deferred_t *deferred;
  js_ref_t *cb;
} sn_async_task_t;

typedef struct sn_async_pwhash_request {
  js_env_t *env;
  js_ref_t *out_ref;
  unsigned char *out_data;
  size_t out_size;
  js_ref_t *pwd_ref;
  const char *pwd_data;
  size_t pwd_size;
  js_ref_t *salt_ref;
  unsigned char *salt;
  uint32_t opslimit;
  uint32_t memlimit;
  uint32_t alg;
} sn_async_pwhash_request;

static void async_pwhash_execute (uv_work_t *uv_req) {
  sn_async_task_t *task = (sn_async_task_t *) uv_req;
  sn_async_pwhash_request *req = (sn_async_pwhash_request *) task->req;
  task->code = crypto_pwhash(req->out_data,
                             req->out_size,
                             req->pwd_data,
                             req->pwd_size,
                             req->salt,
                             req->opslimit,
                             req->memlimit,
                             req->alg);
}

static void async_pwhash_complete (uv_work_t *uv_req, int status) {
  int err;
  sn_async_task_t *task = (sn_async_task_t *) uv_req;
  sn_async_pwhash_request *req = (sn_async_pwhash_request *) task->req;

  js_handle_scope_t *scope;
  err = js_open_handle_scope(req->env, &scope);
  assert(err == 0);

  js_value_t *global;
  err = js_get_global(req->env, &global);
  assert(err == 0);

  SN_ASYNC_COMPLETE("failed to compute password hash")

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);

  err = js_delete_reference(req->env, req->out_ref);
  assert(err == 0);
  err = js_delete_reference(req->env, req->pwd_ref);
  assert(err == 0);
  err = js_delete_reference(req->env, req->salt_ref);
  assert(err == 0);

  free(req);
  free(task);
}

js_value_t *
sn_crypto_pwhash_async (js_env_t *env, js_callback_info_t *info) {
  SN_ARGV_OPTS(6, 7, crypto_pwhash_async)

  SN_ARGV_BUFFER_CAST(unsigned char *, out, 0)
  SN_ARGV_BUFFER_CAST(char *, pwd, 1)
  SN_ARGV_BUFFER_CAST(unsigned char *, salt, 2)
  SN_ARGV_UINT64(opslimit, 3)
  SN_ARGV_UINT64(memlimit, 4)
  SN_ARGV_UINT8(alg, 5)

  SN_ASSERT_MIN_LENGTH(out_size, crypto_pwhash_BYTES_MIN, "out")
  SN_ASSERT_MAX_LENGTH(out_size, crypto_pwhash_BYTES_MAX, "out")
  SN_ASSERT_LENGTH(salt_size, crypto_pwhash_SALTBYTES, "salt")
  SN_ASSERT_MIN_LENGTH(opslimit, crypto_pwhash_OPSLIMIT_MIN, "opslimit")
  SN_ASSERT_MAX_LENGTH(opslimit, crypto_pwhash_OPSLIMIT_MAX, "opslimit")
  SN_ASSERT_MIN_LENGTH(memlimit, crypto_pwhash_MEMLIMIT_MIN, "memlimit")
  SN_ASSERT_MAX_LENGTH(memlimit, (int64_t) crypto_pwhash_MEMLIMIT_MAX, "memlimit")
  SN_THROWS(alg < 1 || alg > 2, "alg must be either Argon2i 1.3 or Argon2id 1.3")
  SN_ASSERT_OPT_CALLBACK(6)

  sn_async_pwhash_request *req = (sn_async_pwhash_request *) malloc(sizeof(sn_async_pwhash_request));

  req->env = env;
  req->out_data = out;
  req->out_size = out_size;
  req->pwd_data = pwd;
  req->pwd_size = pwd_size;
  req->salt = salt;
  req->opslimit = opslimit;
  req->memlimit = memlimit;
  req->alg = alg;

  sn_async_task_t *task = (sn_async_task_t *) malloc(sizeof(sn_async_task_t));
  SN_ASYNC_TASK(6)

  err = js_create_reference(env, out_argv, 1, &req->out_ref);
  assert(err == 0);
  err = js_create_reference(env, pwd_argv, 1, &req->pwd_ref);
  assert(err == 0);
  err = js_create_reference(env, salt_argv, 1, &req->salt_ref);
  assert(err == 0);

  SN_QUEUE_TASK(task, async_pwhash_execute, async_pwhash_complete)

  return promise;
}

typedef struct sn_async_pwhash_str_request {
  uv_work_t task;
  js_env_t *env;
  js_ref_t *out_ref;
  char *out_data;
  js_ref_t *pwd_ref;
  const char *pwd_data;
  size_t pwd_size;
  uint32_t opslimit;
  uint32_t memlimit;
} sn_async_pwhash_str_request;

static void async_pwhash_str_execute (uv_work_t *uv_req) {
  sn_async_task_t *task = (sn_async_task_t *) uv_req;
  sn_async_pwhash_str_request *req = (sn_async_pwhash_str_request *) task->req;
  task->code = crypto_pwhash_str(req->out_data,
                                 req->pwd_data,
                                 req->pwd_size,
                                 req->opslimit,
                                 req->memlimit);
}

static void async_pwhash_str_complete (uv_work_t *uv_req, int status) {
  sn_async_task_t *task = (sn_async_task_t *) uv_req;
  sn_async_pwhash_str_request *req = (sn_async_pwhash_str_request *) task->req;
  int err;
  js_handle_scope_t *scope;
  err = js_open_handle_scope(req->env, &scope);
  assert(err == 0);

  js_value_t *global;
  err = js_get_global(req->env, &global);
  assert(err == 0);

  SN_ASYNC_COMPLETE("failed to compute password hash")

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);

  err = js_delete_reference(req->env, req->out_ref);
  assert(err == 0);
  err = js_delete_reference(req->env, req->pwd_ref);
  assert(err == 0);

  free(req);
  free(task);
}

js_value_t *
sn_crypto_pwhash_str_async (js_env_t *env, js_callback_info_t *info) {
  SN_ARGV_OPTS(4, 5, crypto_pwhash_str_async)

  SN_ARGV_BUFFER_CAST(char *, out, 0)
  SN_ARGV_BUFFER_CAST(char *, pwd, 1)
  SN_ARGV_UINT64(opslimit, 2)
  SN_ARGV_UINT64(memlimit, 3)

  SN_ASSERT_LENGTH(out_size, crypto_pwhash_STRBYTES, "out")
  SN_ASSERT_MIN_LENGTH(opslimit, crypto_pwhash_OPSLIMIT_MIN, "opslimit")
  SN_ASSERT_MAX_LENGTH(opslimit, crypto_pwhash_OPSLIMIT_MAX, "opslimit")
  SN_ASSERT_MIN_LENGTH(memlimit, crypto_pwhash_MEMLIMIT_MIN, "memlimit")
  SN_ASSERT_MAX_LENGTH(memlimit, (int64_t) crypto_pwhash_MEMLIMIT_MAX, "memlimit")
  SN_ASSERT_OPT_CALLBACK(4)

  sn_async_pwhash_str_request *req = (sn_async_pwhash_str_request *) malloc(sizeof(sn_async_pwhash_str_request));
  req->env = env;
  req->out_data = out;
  req->pwd_data = pwd;
  req->pwd_size = pwd_size;
  req->opslimit = opslimit;
  req->memlimit = memlimit;

  sn_async_task_t *task = (sn_async_task_t *) malloc(sizeof(sn_async_task_t));
  SN_ASYNC_TASK(4)

  err = js_create_reference(env, out_argv, 1, &req->out_ref);
  assert(err == 0);
  err = js_create_reference(env, pwd_argv, 1, &req->pwd_ref);
  assert(err == 0);

  SN_QUEUE_TASK(task, async_pwhash_str_execute, async_pwhash_str_complete)

  return promise;
}

typedef struct sn_async_pwhash_str_verify_request {
  uv_work_t task;
  js_env_t *env;
  js_ref_t *str_ref;
  char *str_data;
  js_ref_t *pwd_ref;
  const char *pwd_data;
  size_t pwd_size;
} sn_async_pwhash_str_verify_request;

static void async_pwhash_str_verify_execute (uv_work_t *uv_req) {
  sn_async_task_t *task = (sn_async_task_t *) uv_req;
  sn_async_pwhash_str_verify_request *req = (sn_async_pwhash_str_verify_request *) task->req;
  task->code = crypto_pwhash_str_verify(req->str_data, req->pwd_data, req->pwd_size);
}

static void async_pwhash_str_verify_complete (uv_work_t *uv_req, int status) {
  int err;
  sn_async_task_t *task = (sn_async_task_t *) uv_req;
  sn_async_pwhash_str_verify_request *req = (sn_async_pwhash_str_verify_request *) task->req;

  js_handle_scope_t *scope;
  err = js_open_handle_scope(req->env, &scope);
  assert(err == 0);
  js_value_t *global;
  err = js_get_global(req->env, &global);
  assert(err == 0);

  js_value_t *argv[2];

  // Due to the way that crypto_pwhash_str_verify signals error different
  // from a verification mismatch, we will count all errors as mismatch.
  // The other possible error is wrong argument sizes, which is protected
  // by macros above
  err = js_get_null(req->env, &argv[0]);
  assert(err == 0);
  err = js_get_boolean(req->env, task->code == 0, &argv[1]);
  assert(err == 0);

  switch (task->type) {
  case sn_async_task_t::sn_async_task_promise: {
    err = js_resolve_deferred(req->env, task->deferred, argv[1]);
    assert(err == 0);
    task->deferred = NULL;
    break;
  }

  case sn_async_task_t::sn_async_task_callback: {
    js_value_t *callback;
    err = js_get_reference_value(req->env, task->cb, &callback);
    assert(err == 0);

    js_value_t *return_val;
    SN_CALL_FUNCTION(req->env, global, callback, 2, argv, &return_val)
    break;
  }
  }

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);

  err = js_delete_reference(req->env, req->str_ref);
  assert(err == 0);
  err = js_delete_reference(req->env, req->pwd_ref);
  assert(err == 0);

  free(req);
  free(task);
}

js_value_t *
sn_crypto_pwhash_str_verify_async (js_env_t *env, js_callback_info_t *info) {
  SN_ARGV_OPTS(2, 3, crypto_pwhash_str_async)

  SN_ARGV_BUFFER_CAST(char *, str, 0)
  SN_ARGV_BUFFER_CAST(char *, pwd, 1)

  SN_ASSERT_LENGTH(str_size, crypto_pwhash_STRBYTES, "str")
  SN_ASSERT_OPT_CALLBACK(2)

  sn_async_pwhash_str_verify_request *req = (sn_async_pwhash_str_verify_request *) malloc(sizeof(sn_async_pwhash_str_verify_request));
  req->env = env;
  req->str_data = str;
  req->pwd_data = pwd;
  req->pwd_size = pwd_size;

  sn_async_task_t *task = (sn_async_task_t *) malloc(sizeof(sn_async_task_t));
  SN_ASYNC_TASK(2)

  err = js_create_reference(env, str_argv, 1, &req->str_ref);
  assert(err == 0);
  err = js_create_reference(env, pwd_argv, 1, &req->pwd_ref);
  assert(err == 0);

  SN_QUEUE_TASK(task, async_pwhash_str_verify_execute, async_pwhash_str_verify_complete)

  return promise;
}

typedef struct sn_async_pwhash_scryptsalsa208sha256_request {
  uv_work_t task;
  js_env_t *env;
  js_ref_t *out_ref;
  unsigned char *out_data;
  size_t out_size;
  js_ref_t *pwd_ref;
  const char *pwd_data;
  size_t pwd_size;
  js_ref_t *salt_ref;
  unsigned char *salt;
  uint32_t opslimit;
  uint32_t memlimit;
} sn_async_pwhash_scryptsalsa208sha256_request;

static void async_pwhash_scryptsalsa208sha256_execute (uv_work_t *uv_req) {
  sn_async_task_t *task = (sn_async_task_t *) uv_req;
  sn_async_pwhash_scryptsalsa208sha256_request *req = (sn_async_pwhash_scryptsalsa208sha256_request *) task->req;
  task->code = crypto_pwhash_scryptsalsa208sha256(req->out_data,
                                                  req->out_size,
                                                  req-> pwd_data,
                                                  req->pwd_size,
                                                  req->salt,
                                                  req->opslimit,
                                                  req->memlimit);
}

static void async_pwhash_scryptsalsa208sha256_complete (uv_work_t *uv_req, int status) {
  int err;
  sn_async_task_t *task = (sn_async_task_t *) uv_req;
  sn_async_pwhash_scryptsalsa208sha256_request *req = (sn_async_pwhash_scryptsalsa208sha256_request *) task->req;

  js_handle_scope_t *scope;
  err = js_open_handle_scope(req->env, &scope);
  assert(err == 0);

  js_value_t *global;
  err = js_get_global(req->env, &global);
  assert(err == 0);

  SN_ASYNC_COMPLETE("failed to compute password hash")

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);

  err = js_delete_reference(req->env, req->out_ref);
  assert(err == 0);
  err = js_delete_reference(req->env, req->pwd_ref);
  assert(err == 0);
  err = js_delete_reference(req->env, req->salt_ref);
  assert(err == 0);

  free(req);
  free(task);
}

js_value_t *
sn_crypto_pwhash_scryptsalsa208sha256_async (js_env_t *env, js_callback_info_t *info) {
  SN_ARGV_OPTS(5, 6, crypto_pwhash_scryptsalsa208sha256_async)

  SN_ARGV_BUFFER_CAST(unsigned char *, out, 0)
  SN_ARGV_BUFFER_CAST(char *, pwd, 1)
  SN_ARGV_BUFFER_CAST(unsigned char *, salt, 2)
  SN_ARGV_UINT64(opslimit, 3)
  SN_ARGV_UINT64(memlimit, 4)

  SN_ASSERT_MIN_LENGTH(out_size, crypto_pwhash_scryptsalsa208sha256_BYTES_MIN, "out")
  SN_ASSERT_MAX_LENGTH(out_size, crypto_pwhash_scryptsalsa208sha256_BYTES_MAX, "out")
  SN_ASSERT_LENGTH(salt_size, crypto_pwhash_scryptsalsa208sha256_SALTBYTES, "salt")
  SN_ASSERT_MIN_LENGTH(opslimit, crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN, "opslimit")
  SN_ASSERT_MAX_LENGTH(opslimit, crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX, "opslimit")
  SN_ASSERT_MIN_LENGTH(memlimit, crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN, "memlimit")
  SN_ASSERT_MAX_LENGTH(memlimit, (int64_t) crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX, "memlimit")
  SN_ASSERT_OPT_CALLBACK(5)

  sn_async_pwhash_scryptsalsa208sha256_request *req = (sn_async_pwhash_scryptsalsa208sha256_request *) malloc(sizeof(sn_async_pwhash_scryptsalsa208sha256_request));
  req->env = env;
  req->out_data = out;
  req->out_size = out_size;
  req->pwd_data = pwd;
  req->pwd_size = pwd_size;
  req-> salt = salt;
  req->opslimit = opslimit;
  req->memlimit = memlimit;

  sn_async_task_t *task = (sn_async_task_t *) malloc(sizeof(sn_async_task_t));
  SN_ASYNC_TASK(5)

  err = js_create_reference(env, out_argv, 1, &req->out_ref);
  assert(err == 0);
  err = js_create_reference(env, pwd_argv, 1, &req->pwd_ref);
  assert(err == 0);
  err = js_create_reference(env, salt_argv, 1, &req->salt_ref);
  assert(err == 0);

  SN_QUEUE_TASK(task, async_pwhash_scryptsalsa208sha256_execute, async_pwhash_scryptsalsa208sha256_complete)

  return promise;
}

typedef struct sn_async_pwhash_scryptsalsa208sha256_str_request {
  uv_work_t task;
  js_env_t *env;
  js_ref_t *out_ref;
  char *out_data;
  js_ref_t *pwd_ref;
  const char *pwd_data;
  size_t pwd_size;
  uint32_t opslimit;
  uint32_t memlimit;
} sn_async_pwhash_scryptsalsa208sha256_str_request;

static void async_pwhash_scryptsalsa208sha256_str_execute (uv_work_t *uv_req) {
  sn_async_task_t *task = (sn_async_task_t *) uv_req;
  sn_async_pwhash_scryptsalsa208sha256_str_request *req = (sn_async_pwhash_scryptsalsa208sha256_str_request *) task->req;
  task->code = crypto_pwhash_scryptsalsa208sha256_str(req->out_data,
                                                      req->pwd_data,
                                                      req->pwd_size,
                                                      req->opslimit,
                                                      req->memlimit);
}

static void async_pwhash_scryptsalsa208sha256_str_complete (uv_work_t *uv_req, int status) {
  int err;
  sn_async_task_t *task = (sn_async_task_t *) uv_req;
  sn_async_pwhash_scryptsalsa208sha256_str_request *req = (sn_async_pwhash_scryptsalsa208sha256_str_request *) task->req;

  js_handle_scope_t *scope;
  err = js_open_handle_scope(req->env, &scope);
  assert(err == 0);

  js_value_t *global;
  err = js_get_global(req->env, &global);
  assert(err == 0);

  SN_ASYNC_COMPLETE("failed to compute password hash")

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);

  err = js_delete_reference(req->env, req->out_ref);
  assert(err == 0);
  err = js_delete_reference(req->env, req->pwd_ref);
  assert(err == 0);

  free(req);
  free(task);
}

js_value_t *
sn_crypto_pwhash_scryptsalsa208sha256_str_async (js_env_t *env, js_callback_info_t *info) {
  SN_ARGV_OPTS(4, 5, crypto_pwhash_scryptsalsa208sha256_str_async)

  SN_ARGV_BUFFER_CAST(char *, out, 0)
  SN_ARGV_BUFFER_CAST(char *, pwd, 1)
  SN_ARGV_UINT64(opslimit, 2)
  SN_ARGV_UINT64(memlimit, 3)

  SN_ASSERT_LENGTH(out_size, crypto_pwhash_scryptsalsa208sha256_STRBYTES, "out")
  SN_ASSERT_MIN_LENGTH(opslimit, crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN, "opslimit")
  SN_ASSERT_MAX_LENGTH(opslimit, crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX, "opslimit")
  SN_ASSERT_MIN_LENGTH(memlimit, crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN, "memlimit")
  SN_ASSERT_MAX_LENGTH(memlimit, (int64_t) crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX, "memlimit")
  SN_ASSERT_OPT_CALLBACK(4)

  sn_async_pwhash_scryptsalsa208sha256_str_request *req = (sn_async_pwhash_scryptsalsa208sha256_str_request *) malloc(sizeof(sn_async_pwhash_scryptsalsa208sha256_str_request));
  req->env = env;
  req->out_data = out;
  req->pwd_data = pwd;
  req->pwd_size = pwd_size;
  req->opslimit = opslimit;
  req->memlimit = memlimit;

  sn_async_task_t *task = (sn_async_task_t *) malloc(sizeof(sn_async_task_t));

  SN_ASYNC_TASK(4)

  err = js_create_reference(env, out_argv, 1, &req->out_ref);
  assert(err == 0);
  err = js_create_reference(env, pwd_argv, 1, &req->pwd_ref);
  assert(err == 0);

  SN_QUEUE_TASK(task, async_pwhash_scryptsalsa208sha256_str_execute, async_pwhash_scryptsalsa208sha256_str_complete)

  return promise;
}

typedef struct sn_async_pwhash_scryptsalsa208sha256_str_verify_request {
  uv_work_t task;
  js_env_t *env;
  js_ref_t *str_ref;
  char *str_data;
  js_ref_t *pwd_ref;
  const char *pwd_data;
  size_t pwd_size;
} sn_async_pwhash_scryptsalsa208sha256_str_verify_request;

static void async_pwhash_scryptsalsa208sha256_str_verify_execute (uv_work_t *uv_req) {
  sn_async_task_t *task = (sn_async_task_t *) uv_req;
  sn_async_pwhash_scryptsalsa208sha256_str_verify_request *req = (sn_async_pwhash_scryptsalsa208sha256_str_verify_request *) task->req;
  task->code = crypto_pwhash_scryptsalsa208sha256_str_verify(req->str_data, req->pwd_data, req->pwd_size);
}

static void async_pwhash_scryptsalsa208sha256_str_verify_complete (uv_work_t *uv_req, int status) {
  int err;
  sn_async_task_t *task = (sn_async_task_t *) uv_req;
  sn_async_pwhash_scryptsalsa208sha256_str_verify_request *req = (sn_async_pwhash_scryptsalsa208sha256_str_verify_request *) task->req;

  js_handle_scope_t *scope;
  err = js_open_handle_scope(req->env, &scope);
  assert(err == 0);

  js_value_t *global;
  err = js_get_global(req->env, &global);
  assert(err == 0);

  js_value_t *argv[2];

  // Due to the way that crypto_pwhash_scryptsalsa208sha256_str_verify
  // signal serror different from a verification mismatch, we will count
  // all errors as mismatch. The other possible error is wrong argument
  // sizes, which is protected by macros above
  err = js_get_null(req->env, &argv[0]);
  assert(err == 0);
  err = js_get_boolean(req->env, task->code == 0, &argv[1]);
  assert(err == 0);

  switch (task->type) {
  case sn_async_task_t::sn_async_task_promise: {
    err = js_resolve_deferred(req->env, task->deferred, argv[1]);
    assert(err == 0);
    task->deferred = NULL;
    break;
  }

  case sn_async_task_t::sn_async_task_callback: {
    js_value_t *callback;
    err = js_get_reference_value(req->env, task->cb, &callback);
    assert(err == 0);

    js_value_t *return_val;
    SN_CALL_FUNCTION(req->env, global, callback, 2, argv, &return_val)
    break;
  }
  }

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);

  err = js_delete_reference(req->env, req->str_ref);
  assert(err == 0);
  err = js_delete_reference(req->env, req->pwd_ref);
  assert(err == 0);

  free(req);
  free(task);
}

js_value_t *
sn_crypto_pwhash_scryptsalsa208sha256_str_verify_async (js_env_t *env, js_callback_info_t *info) {
  SN_ARGV_OPTS(2, 3, crypto_pwhash_scryptsalsa208sha256_str_async)

  SN_ARGV_BUFFER_CAST(char *, str, 0)
  SN_ARGV_BUFFER_CAST(char *, pwd, 1)

  SN_ASSERT_LENGTH(str_size, crypto_pwhash_scryptsalsa208sha256_STRBYTES, "str")
  SN_ASSERT_OPT_CALLBACK(2)

  sn_async_pwhash_scryptsalsa208sha256_str_verify_request *req = (sn_async_pwhash_scryptsalsa208sha256_str_verify_request *) malloc(sizeof(sn_async_pwhash_scryptsalsa208sha256_str_verify_request));
  req->env = env;
  req->str_data = str;
  req->pwd_data = pwd;
  req->pwd_size = pwd_size;

  sn_async_task_t *task = (sn_async_task_t *) malloc(sizeof(sn_async_task_t));
  SN_ASYNC_TASK(2)

  err = js_create_reference(env, str_argv, 1, &req->str_ref);
  assert(err == 0);
  err = js_create_reference(env, pwd_argv, 1, &req->pwd_ref);
  assert(err == 0);

  SN_QUEUE_TASK(task, async_pwhash_scryptsalsa208sha256_str_verify_execute, async_pwhash_scryptsalsa208sha256_str_verify_complete)

  return promise;
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
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(state.size_bytes() == sizeof(sn_crypto_stream_xor_state));
  assert(n.size_bytes() == crypto_stream_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_KEYBYTES);

  auto state_data = reinterpret_cast<sn_crypto_stream_xor_state *>(state.data());
  state_data->remainder = 0;
  state_data->block_counter = 0;
  memcpy(state_data->n, n.data(), crypto_stream_NONCEBYTES);
  memcpy(state_data->k, k.data(), crypto_stream_KEYBYTES);
}

static inline void
sn_crypto_stream_xor_wrap_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m
) {
  assert(state.size_bytes() == sizeof(sn_crypto_stream_xor_state));
  assert(c.size_bytes() == m.size_bytes());

  auto state_data = reinterpret_cast<sn_crypto_stream_xor_state *>(state.data());
  auto next_block = state_data->next_block;

  size_t m_size = m.size_bytes();
  auto *c_ptr = c.data();
  auto *m_ptr = m.data();

  if (state_data->remainder) {
    uint64_t offset = 0;
    int rem = state_data->remainder;

    while (rem < 64 && offset < m_size) {
      c_ptr[offset] = next_block[rem] ^ m_ptr[offset];
      ++offset;
      ++rem;
    }

    c_ptr += offset;
    m_ptr += offset;
    m_size -= offset;
    state_data->remainder = (rem == 64) ? 0 : rem;

    if (m_size == 0) return;
  }

  state_data->remainder = m_size & 63;
  size_t main_len = m_size - state_data->remainder;

  crypto_stream_xsalsa20_xor_ic(c_ptr, m_ptr, main_len, state_data->n, state_data->block_counter, state_data->k);
  state_data->block_counter += main_len / 64;

  if (state_data->remainder) {
    sodium_memzero(next_block + state_data->remainder, 64 - state_data->remainder);
    memcpy(next_block, m_ptr + main_len, state_data->remainder);

    crypto_stream_xsalsa20_xor_ic(
      next_block, next_block, 64, state_data->n, state_data->block_counter, state_data->k
    );
    memcpy(c_ptr + main_len, next_block, state_data->remainder);

    state_data->block_counter++;
  }
}

static inline void
sn_crypto_stream_xor_wrap_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state
) {
  assert(state.size_bytes() == sizeof(sn_crypto_stream_xor_state));
  auto state_data = reinterpret_cast<sn_crypto_stream_xor_state *>(state.data());

  sodium_memzero(state_data->n, sizeof(state_data->n));
  sodium_memzero(state_data->k, sizeof(state_data->k));
  sodium_memzero(state_data->next_block, sizeof(state_data->next_block));
  state_data->remainder = 0;
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
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(state.size_bytes() == sizeof(sn_crypto_stream_chacha20_xor_state));
  assert(n.size_bytes() == crypto_stream_chacha20_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_chacha20_KEYBYTES);

  auto state_data = reinterpret_cast<sn_crypto_stream_chacha20_xor_state *>(state.data());
  state_data->remainder = 0;
  state_data->block_counter = 0;
  memcpy(state_data->n, n.data(), crypto_stream_chacha20_NONCEBYTES);
  memcpy(state_data->k, k.data(), crypto_stream_chacha20_KEYBYTES);
}

static inline void
sn_crypto_stream_chacha20_xor_wrap_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m
) {
  assert(state.size_bytes() == sizeof(sn_crypto_stream_chacha20_xor_state));
  assert(c.size_bytes() == m.size_bytes());

  auto state_data = reinterpret_cast<sn_crypto_stream_chacha20_xor_state *>(state.data());
  auto *next_block = state_data->next_block;

  size_t m_size = m.size_bytes();
  auto *c_ptr = c.data();
  auto *m_ptr = m.data();

  if (state_data->remainder) {
    uint64_t offset = 0;
    int rem = state_data->remainder;

    while (rem < 64 && offset < m_size) {
      c_ptr[offset] = next_block[rem] ^ m_ptr[offset];
      offset++;
      rem++;
    }

    c_ptr += offset;
    m_ptr += offset;
    m_size -= offset;
    state_data->remainder = (rem == 64) ? 0 : rem;

    if (m_size == 0) return;
  }

  state_data->remainder = m_size & 63;
  size_t main_len = m_size - state_data->remainder;

  crypto_stream_chacha20_xor_ic(
    c_ptr, m_ptr, main_len,
    state_data->n,
    state_data->block_counter,
    state_data->k
  );

  state_data->block_counter += main_len / 64;

  if (state_data->remainder) {
    sodium_memzero(next_block + state_data->remainder, 64 - state_data->remainder);
    memcpy(next_block, m_ptr + main_len, state_data->remainder);

    crypto_stream_chacha20_xor_ic(
      next_block, next_block, 64,
      state_data->n,
      state_data->block_counter,
      state_data->k
    );
    memcpy(c_ptr + main_len, next_block, state_data->remainder);

    state_data->block_counter++;
  }
}

static inline void
sn_crypto_stream_chacha20_xor_wrap_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state
) {
  assert(state.size_bytes() == sizeof(sn_crypto_stream_chacha20_xor_state));
  auto state_data = reinterpret_cast<sn_crypto_stream_chacha20_xor_state *>(state.data());

  sodium_memzero(state_data->n, sizeof(state_data->n));
  sodium_memzero(state_data->k, sizeof(state_data->k));
  sodium_memzero(state_data->next_block, sizeof(state_data->next_block));
  state_data->remainder = 0;
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
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(state.size_bytes() == sizeof(sn_crypto_stream_chacha20_ietf_xor_state));
  assert(n.size_bytes() == crypto_stream_chacha20_ietf_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_chacha20_ietf_KEYBYTES);

  auto state_data = reinterpret_cast<sn_crypto_stream_chacha20_ietf_xor_state *>(state.data());
  state_data->remainder = 0;
  state_data->block_counter = 0;
  memcpy(state_data->n, n.data(), crypto_stream_chacha20_ietf_NONCEBYTES);
  memcpy(state_data->k, k.data(), crypto_stream_chacha20_ietf_KEYBYTES);
}

static inline void
sn_crypto_stream_chacha20_ietf_xor_wrap_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m
) {
  assert(state.size_bytes() == sizeof(sn_crypto_stream_chacha20_ietf_xor_state));
  assert(c.size_bytes() == m.size_bytes());

  auto state_data = reinterpret_cast<sn_crypto_stream_chacha20_ietf_xor_state *>(state.data());
  auto *next_block = state_data->next_block;

  size_t m_size = m.size_bytes();
  auto *c_ptr = c.data();
  auto *m_ptr = m.data();

  if (state_data->remainder) {
    uint64_t offset = 0;
    int rem = state_data->remainder;

    while (rem < 64 && offset < m_size) {
      c_ptr[offset] = next_block[rem] ^ m_ptr[offset];
      offset++;
      rem++;
    }

    c_ptr += offset;
    m_ptr += offset;
    m_size -= offset;
    state_data->remainder = (rem == 64) ? 0 : rem;

    if (m_size == 0) return;
  }

  state_data->remainder = m_size & 63;
  size_t main_len = m_size - state_data->remainder;

  crypto_stream_chacha20_ietf_xor_ic(
    c_ptr, m_ptr, main_len,
    state_data->n,
    state_data->block_counter,
    state_data->k
  );

  state_data->block_counter += main_len / 64;

  if (state_data->remainder) {
    sodium_memzero(next_block + state_data->remainder, 64 - state_data->remainder);
    memcpy(next_block, m_ptr + main_len, state_data->remainder);

    crypto_stream_chacha20_ietf_xor_ic(
      next_block, next_block, 64,
      state_data->n,
      state_data->block_counter,
      state_data->k
    );
    memcpy(c_ptr + main_len, next_block, state_data->remainder);

    state_data->block_counter++;
  }
}

static inline void
sn_crypto_stream_chacha20_ietf_xor_wrap_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state
) {
  assert(state.size_bytes() == sizeof(sn_crypto_stream_chacha20_ietf_xor_state));
  auto state_data = reinterpret_cast<sn_crypto_stream_chacha20_ietf_xor_state *>(state.data());

  sodium_memzero(state_data->n, sizeof(state_data->n));
  sodium_memzero(state_data->k, sizeof(state_data->k));
  sodium_memzero(state_data->next_block, sizeof(state_data->next_block));
  state_data->remainder = 0;
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
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(state.size_bytes() == sizeof(sn_crypto_stream_xchacha20_xor_state));
  assert(n.size_bytes() == crypto_stream_xchacha20_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_xchacha20_KEYBYTES);

  auto state_data = reinterpret_cast<sn_crypto_stream_xchacha20_xor_state *>(state.data());
  state_data->remainder = 0;
  state_data->block_counter = 0;
  memcpy(state_data->n, n.data(), crypto_stream_xchacha20_NONCEBYTES);
  memcpy(state_data->k, k.data(), crypto_stream_xchacha20_KEYBYTES);
}

static inline void
sn_crypto_stream_xchacha20_xor_wrap_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m
) {
  assert(state.size_bytes() == sizeof(sn_crypto_stream_xchacha20_xor_state));
  assert(c.size_bytes() == m.size_bytes());

  auto state_data = reinterpret_cast<sn_crypto_stream_xchacha20_xor_state *>(state.data());
  auto *next_block = state_data->next_block;

  size_t m_size = m.size_bytes();
  auto *c_ptr = c.data();
  auto *m_ptr = m.data();

  if (state_data->remainder) {
    uint64_t offset = 0;
    int rem = state_data->remainder;

    while (rem < 64 && offset < m_size) {
      c_ptr[offset] = next_block[rem] ^ m_ptr[offset];
      ++offset;
      ++rem;
    }

    c_ptr += offset;
    m_ptr += offset;
    m_size -= offset;
    state_data->remainder = (rem == 64) ? 0 : rem;

    if (m_size == 0) return;
  }

  state_data->remainder = m_size & 63;
  size_t main_len = m_size - state_data->remainder;

  crypto_stream_xchacha20_xor_ic(
    c_ptr, m_ptr, main_len,
    state_data->n,
    state_data->block_counter,
    state_data->k
  );

  state_data->block_counter += main_len / 64;

  if (state_data->remainder) {
    sodium_memzero(next_block + state_data->remainder, 64 - state_data->remainder);
    memcpy(next_block, m_ptr + main_len, state_data->remainder);

    crypto_stream_xchacha20_xor_ic(
      next_block, next_block, 64,
      state_data->n,
      state_data->block_counter,
      state_data->k
    );
    memcpy(c_ptr + main_len, next_block, state_data->remainder);

    state_data->block_counter++;
  }
}

static inline void
sn_crypto_stream_xchacha20_xor_wrap_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state
) {
  assert(state.size_bytes() == sizeof(sn_crypto_stream_xchacha20_xor_state));
  auto state_data = reinterpret_cast<sn_crypto_stream_xchacha20_xor_state *>(state.data());

  sodium_memzero(state_data->n, sizeof(state_data->n));
  sodium_memzero(state_data->k, sizeof(state_data->k));
  sodium_memzero(state_data->next_block, sizeof(state_data->next_block));
  state_data->remainder = 0;
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
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> n,
  js_typedarray_span_t<> k
) {
  assert(state.size_bytes() == sizeof(sn_crypto_stream_salsa20_xor_state));
  assert(n.size_bytes() == crypto_stream_salsa20_NONCEBYTES);
  assert(k.size_bytes() == crypto_stream_salsa20_KEYBYTES);

  auto state_data = reinterpret_cast<sn_crypto_stream_salsa20_xor_state *>(state.data());
  state_data->remainder = 0;
  state_data->block_counter = 0;
  memcpy(state_data->n, n.data(), crypto_stream_salsa20_NONCEBYTES);
  memcpy(state_data->k, k.data(), crypto_stream_salsa20_KEYBYTES);
}

static inline void
sn_crypto_stream_salsa20_xor_wrap_update(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state,
  js_typedarray_span_t<> c,
  js_typedarray_span_t<> m
) {
  assert(state.size_bytes() == sizeof(sn_crypto_stream_salsa20_xor_state));
  assert(c.size_bytes() == m.size_bytes());

  auto state_data = reinterpret_cast<sn_crypto_stream_salsa20_xor_state *>(state.data());
  auto *next_block = state_data->next_block;

  size_t m_size = m.size_bytes();
  auto *c_ptr = c.data();
  auto *m_ptr = m.data();

  if (state_data->remainder) {
    uint64_t offset = 0;
    int rem = state_data->remainder;

    while (rem < 64 && offset < m_size) {
      c_ptr[offset] = next_block[rem] ^ m_ptr[offset];
      ++offset;
      ++rem;
    }

    c_ptr += offset;
    m_ptr += offset;
    m_size -= offset;
    state_data->remainder = (rem == 64) ? 0 : rem;

    if (m_size == 0) return;
  }

  state_data->remainder = m_size & 63;
  size_t main_len = m_size - state_data->remainder;

  crypto_stream_salsa20_xor_ic(
    c_ptr, m_ptr, main_len,
    state_data->n,
    state_data->block_counter,
    state_data->k
  );

  state_data->block_counter += main_len / 64;

  if (state_data->remainder) {
    sodium_memzero(next_block + state_data->remainder, 64 - state_data->remainder);
    memcpy(next_block, m_ptr + main_len, state_data->remainder);

    crypto_stream_salsa20_xor_ic(
      next_block, next_block, 64,
      state_data->n,
      state_data->block_counter,
      state_data->k
    );
    memcpy(c_ptr + main_len, next_block, state_data->remainder);

    state_data->block_counter++;
  }
}

static inline void
sn_crypto_stream_salsa20_xor_wrap_final(
  js_env_t *,
  js_receiver_t,
  js_typedarray_span_t<> state
) {
  assert(state.size_bytes() == sizeof(sn_crypto_stream_salsa20_xor_state));
  auto state_data = reinterpret_cast<sn_crypto_stream_salsa20_xor_state *>(state.data());

  sodium_memzero(state_data->n, sizeof(state_data->n));
  sodium_memzero(state_data->k, sizeof(state_data->k));
  sodium_memzero(state_data->next_block, sizeof(state_data->next_block));
  state_data->remainder = 0;
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
  int64_t iter,
  int64_t outlen
) {

  assert(static_cast<uint64_t>(iter) >= sn__extension_pbkdf2_sha512_ITERATIONS_MIN);
  assert(static_cast<uint64_t>(outlen) <= sn__extension_pbkdf2_sha512_BYTES_MAX);
  assert(out.size_bytes() >= static_cast<size_t>(outlen));

  return sn__extension_pbkdf2_sha512(
    passwd.data(),
    passwd.size_bytes(),
    salt.data(),
    salt.size_bytes(),
    static_cast<uint64_t>(iter),
    out.data(),
    static_cast<uint64_t>(outlen)
  );
}

typedef struct sn_async_pbkdf2_sha512_request {
  js_env_t *env;
  unsigned char *out_data;
  size_t out_size;
  js_ref_t *out_ref;
  size_t outlen;
  js_ref_t *pwd_ref;
  const unsigned char *pwd_data;
  size_t pwd_size;
  js_ref_t *salt_ref;
  unsigned char *salt_data;
  size_t salt_size;
  uint64_t iter;
} sn_async_pbkdf2_sha512_request;

static void async_pbkdf2_sha512_execute (uv_work_t *uv_req) {
  sn_async_task_t *task = (sn_async_task_t *) uv_req;
  sn_async_pbkdf2_sha512_request *req = (sn_async_pbkdf2_sha512_request *) task->req;
  task->code = sn__extension_pbkdf2_sha512(req->pwd_data,
                                    req->pwd_size,
                                    req->salt_data,
                                    req->salt_size,
                                    req->iter,
                                    req->out_data,
                                    req->outlen);
}

static void async_pbkdf2_sha512_complete (uv_work_t *uv_req, int status) {
  int err;
  sn_async_task_t *task = (sn_async_task_t *) uv_req;
  sn_async_pbkdf2_sha512_request *req = (sn_async_pbkdf2_sha512_request *) task->req;

  js_handle_scope_t *scope;
  err = js_open_handle_scope(req->env, &scope);
  assert(err == 0);

  js_value_t *global;
  err = js_get_global(req->env, &global);
  assert(err == 0);

  SN_ASYNC_COMPLETE("failed to compute kdf")

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);

  err = js_delete_reference(req->env, req->out_ref);
  assert(err == 0);
  err = js_delete_reference(req->env, req->pwd_ref);
  assert(err == 0);
  err = js_delete_reference(req->env, req->salt_ref);
  assert(err == 0);

  free(req);
  free(task);
}

js_value_t *
sn_extension_pbkdf2_sha512_async (js_env_t *env, js_callback_info_t *info) {
  SN_ARGV_OPTS(5, 6, extension_pbkdf2_sha512_async)

  SN_ARGV_BUFFER_CAST(unsigned char *, out, 0)
  SN_ARGV_BUFFER_CAST(unsigned char *, pwd, 1)
  SN_ARGV_BUFFER_CAST(unsigned char *, salt, 2)
  SN_ARGV_UINT64(iter, 3)
  SN_ARGV_UINT64(outlen, 4)

  SN_ASSERT_MIN_LENGTH(iter, sn__extension_pbkdf2_sha512_ITERATIONS_MIN, "iterations")
  SN_ASSERT_MAX_LENGTH(outlen, sn__extension_pbkdf2_sha512_BYTES_MAX, "outlen")
  SN_ASSERT_MIN_LENGTH(out_size, outlen, "output")
  SN_ASSERT_OPT_CALLBACK(5)

  sn_async_pbkdf2_sha512_request *req = (sn_async_pbkdf2_sha512_request *) malloc(sizeof(sn_async_pbkdf2_sha512_request));

  req->env = env;
  req->out_data = out;
  req->out_size = out_size;
  req->pwd_data = pwd;
  req->pwd_size = pwd_size;
  req->salt_data = salt;
  req->salt_size = salt_size;
  req->iter = iter;
  req->outlen = outlen;

  sn_async_task_t *task = (sn_async_task_t *) malloc(sizeof(sn_async_task_t));
  SN_ASYNC_TASK(5);

  err = js_create_reference(env, out_argv, 1, &req->out_ref);
  assert(err == 0);
  err = js_create_reference(env, pwd_argv, 1, &req->pwd_ref);
  assert(err == 0);
  err = js_create_reference(env, salt_argv, 1, &req->salt_ref);
  assert(err == 0);

  SN_QUEUE_TASK(task, async_pbkdf2_sha512_execute, async_pbkdf2_sha512_complete)

  return promise;
}

js_value_t *
sodium_native_exports (js_env_t *env, js_value_t *exports) {
  int err;
  err = sodium_init();
  SN_THROWS(err == -1, "sodium_init() failed")

  js_object_t _exports = static_cast<js_object_t>(exports); // TODO: remove

  // TODO: rename => SN_EXPORT_FUNCTION
#define SN_EXPORT_FUNCTION_SCOPED(name, fn) \
  err = js_set_property<fn, js_function_options_t{ .scoped=false }>(env, _exports, name); \
  assert(err == 0);

#define SN_EXPORT_FUNCTION_NOSCOPE(name, fn) \
  err = js_set_property<fn, js_function_options_t{}>(env, _exports, name); \
  assert(err == 0);

  // memory

  SN_EXPORT_FUNCTION_SCOPED("sodium_memzero", sn_sodium_memzero);
  SN_EXPORT_FUNCTION_SCOPED("sodium_mlock", sn_sodium_mlock);
  SN_EXPORT_FUNCTION_SCOPED("sodium_munlock", sn_sodium_munlock);
  SN_EXPORT_FUNCTION_SCOPED("sodium_malloc", sn_sodium_malloc);
  SN_EXPORT_FUNCTION_SCOPED("sodium_free", sn_sodium_free);
  SN_EXPORT_FUNCTION_SCOPED("sodium_mprotect_noaccess", sn_sodium_mprotect_noaccess);
  SN_EXPORT_FUNCTION_SCOPED("sodium_mprotect_readonly", sn_sodium_mprotect_readonly);
  SN_EXPORT_FUNCTION_SCOPED("sodium_mprotect_readwrite", sn_sodium_mprotect_readwrite);

  // randombytes

  SN_EXPORT_FUNCTION_NOSCOPE("randombytes_buf", sn_randombytes_buf);
  SN_EXPORT_FUNCTION_NOSCOPE("randombytes_buf_deterministic", sn_randombytes_buf_deterministic);
  SN_EXPORT_FUNCTION_NOSCOPE("randombytes_random", sn_randombytes_random);
  SN_EXPORT_FUNCTION_NOSCOPE("randombytes_uniform", sn_randombytes_uniform);

  SN_EXPORT_UINT32(randombytes_SEEDBYTES, randombytes_SEEDBYTES);

  // sodium helpers

  SN_EXPORT_FUNCTION_SCOPED("sodium_memcmp", sn_sodium_memcmp);
  SN_EXPORT_FUNCTION_SCOPED("sodium_increment", sn_sodium_increment);
  SN_EXPORT_FUNCTION_SCOPED("sodium_add", sn_sodium_add);
  SN_EXPORT_FUNCTION_SCOPED("sodium_sub", sn_sodium_sub);
  SN_EXPORT_FUNCTION_SCOPED("sodium_compare", sn_sodium_compare);
  SN_EXPORT_FUNCTION_SCOPED("sodium_is_zero", sn_sodium_is_zero);
  SN_EXPORT_FUNCTION_SCOPED("sodium_pad", sn_sodium_pad);
  SN_EXPORT_FUNCTION_SCOPED("sodium_unpad", sn_sodium_unpad);

  // crypto_aead

  SN_EXPORT_FUNCTION_SCOPED("crypto_aead_xchacha20poly1305_ietf_keygen", sn_crypto_aead_xchacha20poly1305_ietf_keygen);
  SN_EXPORT_FUNCTION_SCOPED("crypto_aead_xchacha20poly1305_ietf_encrypt", sn_crypto_aead_xchacha20poly1305_ietf_encrypt);
  SN_EXPORT_FUNCTION_SCOPED("crypto_aead_xchacha20poly1305_ietf_decrypt", sn_crypto_aead_xchacha20poly1305_ietf_decrypt);
  SN_EXPORT_FUNCTION_SCOPED("crypto_aead_xchacha20poly1305_ietf_encrypt_detached", sn_crypto_aead_xchacha20poly1305_ietf_encrypt_detached);
  SN_EXPORT_FUNCTION_SCOPED("crypto_aead_xchacha20poly1305_ietf_decrypt_detached", sn_crypto_aead_xchacha20poly1305_ietf_decrypt_detached);
  SN_EXPORT_UINT32(crypto_aead_xchacha20poly1305_ietf_ABYTES, crypto_aead_xchacha20poly1305_ietf_ABYTES);
  SN_EXPORT_UINT32(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  SN_EXPORT_UINT32(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  SN_EXPORT_UINT32(crypto_aead_xchacha20poly1305_ietf_NSECBYTES, crypto_aead_xchacha20poly1305_ietf_NSECBYTES);
  SN_EXPORT_UINT64(crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX, crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX);

  SN_EXPORT_FUNCTION_SCOPED("crypto_aead_chacha20poly1305_ietf_keygen", sn_crypto_aead_chacha20poly1305_ietf_keygen);
  SN_EXPORT_FUNCTION_SCOPED("crypto_aead_chacha20poly1305_ietf_encrypt", sn_crypto_aead_chacha20poly1305_ietf_encrypt);
  SN_EXPORT_FUNCTION_SCOPED("crypto_aead_chacha20poly1305_ietf_decrypt", sn_crypto_aead_chacha20poly1305_ietf_decrypt);
  SN_EXPORT_FUNCTION_SCOPED("crypto_aead_chacha20poly1305_ietf_encrypt_detached", sn_crypto_aead_chacha20poly1305_ietf_encrypt_detached);
  SN_EXPORT_FUNCTION_SCOPED("crypto_aead_chacha20poly1305_ietf_decrypt_detached", sn_crypto_aead_chacha20poly1305_ietf_decrypt_detached);
  SN_EXPORT_UINT32(crypto_aead_chacha20poly1305_ietf_ABYTES, crypto_aead_chacha20poly1305_ietf_ABYTES);
  SN_EXPORT_UINT32(crypto_aead_chacha20poly1305_ietf_KEYBYTES, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
  SN_EXPORT_UINT32(crypto_aead_chacha20poly1305_ietf_NPUBBYTES, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  SN_EXPORT_UINT32(crypto_aead_chacha20poly1305_ietf_NSECBYTES, crypto_aead_chacha20poly1305_ietf_NSECBYTES);
  SN_EXPORT_UINT64(crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX, crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX);

  // crypto_auth

  SN_EXPORT_FUNCTION_SCOPED("crypto_auth", sn_crypto_auth);
  SN_EXPORT_FUNCTION_SCOPED("crypto_auth_verify", sn_crypto_auth_verify);
  SN_EXPORT_UINT32(crypto_auth_BYTES, crypto_auth_BYTES);
  SN_EXPORT_UINT32(crypto_auth_KEYBYTES, crypto_auth_KEYBYTES);
  SN_EXPORT_STRING(crypto_auth_PRIMITIVE, crypto_auth_PRIMITIVE);

  // crypto_box

  SN_EXPORT_FUNCTION_SCOPED("crypto_box_keypair", sn_crypto_box_keypair);
  SN_EXPORT_FUNCTION_SCOPED("crypto_box_seed_keypair", sn_crypto_box_seed_keypair);
  SN_EXPORT_FUNCTION_SCOPED("crypto_box_easy", sn_crypto_box_easy);
  SN_EXPORT_FUNCTION_SCOPED("crypto_box_open_easy", sn_crypto_box_open_easy);
  SN_EXPORT_FUNCTION_SCOPED("crypto_box_detached", sn_crypto_box_detached);
  SN_EXPORT_FUNCTION_SCOPED("crypto_box_open_detached", sn_crypto_box_open_detached);
  SN_EXPORT_FUNCTION_SCOPED("crypto_box_seal", sn_crypto_box_seal);
  SN_EXPORT_FUNCTION_NOSCOPE("crypto_box_seal_open", sn_crypto_box_seal_open);

  SN_EXPORT_UINT32(crypto_box_SEEDBYTES, crypto_box_SEEDBYTES);
  SN_EXPORT_UINT32(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
  SN_EXPORT_UINT32(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
  SN_EXPORT_UINT32(crypto_box_NONCEBYTES, crypto_box_NONCEBYTES);
  SN_EXPORT_UINT32(crypto_box_MACBYTES, crypto_box_MACBYTES);
  SN_EXPORT_UINT32(crypto_box_SEALBYTES, crypto_box_SEALBYTES);
  SN_EXPORT_STRING(crypto_box_PRIMITIVE, crypto_box_PRIMITIVE);

  // crypto_core

  SN_EXPORT_FUNCTION_SCOPED("crypto_core_ed25519_is_valid_point", sn_crypto_core_ed25519_is_valid_point);
  SN_EXPORT_FUNCTION_SCOPED("crypto_core_ed25519_from_uniform", sn_crypto_core_ed25519_from_uniform);
  SN_EXPORT_FUNCTION_SCOPED("crypto_core_ed25519_add", sn_crypto_core_ed25519_add);
  SN_EXPORT_FUNCTION_SCOPED("crypto_core_ed25519_sub", sn_crypto_core_ed25519_sub);
  SN_EXPORT_FUNCTION_SCOPED("crypto_core_ed25519_scalar_random", sn_crypto_core_ed25519_scalar_random);
  SN_EXPORT_FUNCTION_SCOPED("crypto_core_ed25519_scalar_reduce", sn_crypto_core_ed25519_scalar_reduce);
  SN_EXPORT_FUNCTION_SCOPED("crypto_core_ed25519_scalar_invert", sn_crypto_core_ed25519_scalar_invert);
  SN_EXPORT_FUNCTION_SCOPED("crypto_core_ed25519_scalar_negate", sn_crypto_core_ed25519_scalar_negate);
  SN_EXPORT_FUNCTION_SCOPED("crypto_core_ed25519_scalar_complement", sn_crypto_core_ed25519_scalar_complement);
  SN_EXPORT_FUNCTION_SCOPED("crypto_core_ed25519_scalar_add", sn_crypto_core_ed25519_scalar_add);
  SN_EXPORT_FUNCTION_SCOPED("crypto_core_ed25519_scalar_sub", sn_crypto_core_ed25519_scalar_sub);
  SN_EXPORT_UINT32(crypto_core_ed25519_BYTES, crypto_core_ed25519_BYTES);
  SN_EXPORT_UINT32(crypto_core_ed25519_UNIFORMBYTES, crypto_core_ed25519_UNIFORMBYTES);
  SN_EXPORT_UINT32(crypto_core_ed25519_SCALARBYTES, crypto_core_ed25519_SCALARBYTES);
  SN_EXPORT_UINT32(crypto_core_ed25519_NONREDUCEDSCALARBYTES, crypto_core_ed25519_NONREDUCEDSCALARBYTES);

  // crypto_kdf

  SN_EXPORT_FUNCTION_SCOPED("crypto_kdf_keygen", sn_crypto_kdf_keygen);
  SN_EXPORT_FUNCTION_SCOPED("crypto_kdf_derive_from_key", sn_crypto_kdf_derive_from_key);
  SN_EXPORT_UINT32(crypto_kdf_BYTES_MIN, crypto_kdf_BYTES_MIN);
  SN_EXPORT_UINT32(crypto_kdf_BYTES_MAX, crypto_kdf_BYTES_MAX);
  SN_EXPORT_UINT32(crypto_kdf_CONTEXTBYTES, crypto_kdf_CONTEXTBYTES);
  SN_EXPORT_UINT32(crypto_kdf_KEYBYTES, crypto_kdf_KEYBYTES);
  SN_EXPORT_STRING(crypto_kdf_PRIMITIVE, crypto_kdf_PRIMITIVE);

  // crypto_kx

  SN_EXPORT_FUNCTION_SCOPED("crypto_kx_keypair", sn_crypto_kx_keypair);
  SN_EXPORT_FUNCTION_SCOPED("crypto_kx_seed_keypair", sn_crypto_kx_seed_keypair);
  SN_EXPORT_FUNCTION_SCOPED("crypto_kx_client_session_keys", sn_crypto_kx_client_session_keys);
  SN_EXPORT_FUNCTION_SCOPED("crypto_kx_server_session_keys", sn_crypto_kx_server_session_keys);
  SN_EXPORT_UINT32(crypto_kx_PUBLICKEYBYTES, crypto_kx_PUBLICKEYBYTES);
  SN_EXPORT_UINT32(crypto_kx_SECRETKEYBYTES, crypto_kx_SECRETKEYBYTES);
  SN_EXPORT_UINT32(crypto_kx_SEEDBYTES, crypto_kx_SEEDBYTES);
  SN_EXPORT_UINT32(crypto_kx_SESSIONKEYBYTES, crypto_kx_SESSIONKEYBYTES);
  SN_EXPORT_STRING(crypto_kx_PRIMITIVE, crypto_kx_PRIMITIVE);

  // crypto_generichash

  SN_EXPORT_FUNCTION_NOSCOPE("crypto_generichash", sn_crypto_generichash);
  SN_EXPORT_FUNCTION_SCOPED("crypto_generichash_batch", sn_crypto_generichash_batch);
  SN_EXPORT_FUNCTION_NOSCOPE("crypto_generichash_batch", sn_crypto_generichash_batch);
  SN_EXPORT_FUNCTION_NOSCOPE("crypto_generichash_keygen", sn_crypto_generichash_keygen);
  SN_EXPORT_FUNCTION_NOSCOPE("crypto_generichash_init", sn_crypto_generichash_init);
  SN_EXPORT_FUNCTION_NOSCOPE("crypto_generichash_update", sn_crypto_generichash_update);
  SN_EXPORT_FUNCTION_NOSCOPE("crypto_generichash_final", sn_crypto_generichash_final);

  SN_EXPORT_UINT32(crypto_generichash_STATEBYTES, sizeof(crypto_generichash_state));
  SN_EXPORT_STRING(crypto_generichash_PRIMITIVE, crypto_generichash_PRIMITIVE);
  SN_EXPORT_UINT32(crypto_generichash_BYTES_MIN, crypto_generichash_BYTES_MIN);
  SN_EXPORT_UINT32(crypto_generichash_BYTES_MAX, crypto_generichash_BYTES_MAX);
  SN_EXPORT_UINT32(crypto_generichash_BYTES, crypto_generichash_BYTES);
  SN_EXPORT_UINT32(crypto_generichash_KEYBYTES_MIN, crypto_generichash_KEYBYTES_MIN);
  SN_EXPORT_UINT32(crypto_generichash_KEYBYTES_MAX, crypto_generichash_KEYBYTES_MAX);
  SN_EXPORT_UINT32(crypto_generichash_KEYBYTES, crypto_generichash_KEYBYTES);

  // crypto_hash

  SN_EXPORT_FUNCTION_SCOPED("crypto_hash", sn_crypto_hash);
  SN_EXPORT_UINT32(crypto_hash_BYTES, crypto_hash_BYTES);
  SN_EXPORT_STRING(crypto_hash_PRIMITIVE, crypto_hash_PRIMITIVE);

  SN_EXPORT_FUNCTION_SCOPED("crypto_hash_sha256", sn_crypto_hash_sha256);
  SN_EXPORT_FUNCTION_SCOPED("crypto_hash_sha256_init", sn_crypto_hash_sha256_init);
  SN_EXPORT_FUNCTION_SCOPED("crypto_hash_sha256_update", sn_crypto_hash_sha256_update);
  SN_EXPORT_FUNCTION_SCOPED("crypto_hash_sha256_final", sn_crypto_hash_sha256_final);
  SN_EXPORT_UINT32(crypto_hash_sha256_STATEBYTES, sizeof(crypto_hash_sha256_state));
  SN_EXPORT_UINT32(crypto_hash_sha256_BYTES, crypto_hash_sha256_BYTES);

  SN_EXPORT_FUNCTION_SCOPED("crypto_hash_sha512", sn_crypto_hash_sha512);
  SN_EXPORT_FUNCTION_SCOPED("crypto_hash_sha512_init", sn_crypto_hash_sha512_init);
  SN_EXPORT_FUNCTION_SCOPED("crypto_hash_sha512_update", sn_crypto_hash_sha512_update);
  SN_EXPORT_FUNCTION_SCOPED("crypto_hash_sha512_final", sn_crypto_hash_sha512_final);
  SN_EXPORT_UINT32(crypto_hash_sha512_STATEBYTES, sizeof(crypto_hash_sha512_state));
  SN_EXPORT_UINT32(crypto_hash_sha512_BYTES, crypto_hash_sha512_BYTES);

  // crypto_onetimeauth

  SN_EXPORT_FUNCTION_SCOPED("crypto_onetimeauth", sn_crypto_onetimeauth);
  SN_EXPORT_FUNCTION_SCOPED("crypto_onetimeauth_verify", sn_crypto_onetimeauth_verify);
  SN_EXPORT_FUNCTION_SCOPED("crypto_onetimeauth_init", sn_crypto_onetimeauth_init);
  SN_EXPORT_FUNCTION_SCOPED("crypto_onetimeauth_update", sn_crypto_onetimeauth_update);
  SN_EXPORT_FUNCTION_SCOPED("crypto_onetimeauth_final", sn_crypto_onetimeauth_final);
  SN_EXPORT_UINT32(crypto_onetimeauth_STATEBYTES, sizeof(crypto_onetimeauth_state));
  SN_EXPORT_UINT32(crypto_onetimeauth_BYTES, crypto_onetimeauth_BYTES);
  SN_EXPORT_UINT32(crypto_onetimeauth_KEYBYTES, crypto_onetimeauth_KEYBYTES);
  SN_EXPORT_STRING(crypto_onetimeauth_PRIMITIVE, crypto_onetimeauth_PRIMITIVE);

  // crypto_pwhash

  SN_EXPORT_FUNCTION_SCOPED("crypto_pwhash", sn_crypto_pwhash);
  SN_EXPORT_FUNCTION_SCOPED("crypto_pwhash_str", sn_crypto_pwhash_str);
  SN_EXPORT_FUNCTION_SCOPED("crypto_pwhash_str_verify", sn_crypto_pwhash_str_verify);
  SN_EXPORT_FUNCTION_SCOPED("crypto_pwhash_str_needs_rehash", sn_crypto_pwhash_str_needs_rehash);
  SN_EXPORT_FUNCTION(crypto_pwhash_async, sn_crypto_pwhash_async);
  SN_EXPORT_FUNCTION(crypto_pwhash_str_async, sn_crypto_pwhash_str_async);
  SN_EXPORT_FUNCTION(crypto_pwhash_str_verify_async, sn_crypto_pwhash_str_verify_async);
  SN_EXPORT_UINT32(crypto_pwhash_ALG_ARGON2I13, crypto_pwhash_ALG_ARGON2I13);
  SN_EXPORT_UINT32(crypto_pwhash_ALG_ARGON2ID13, crypto_pwhash_ALG_ARGON2ID13);
  SN_EXPORT_UINT32(crypto_pwhash_ALG_DEFAULT, crypto_pwhash_ALG_DEFAULT);
  SN_EXPORT_UINT32(crypto_pwhash_BYTES_MIN, crypto_pwhash_BYTES_MIN);
  SN_EXPORT_UINT32(crypto_pwhash_BYTES_MAX, crypto_pwhash_BYTES_MAX);
  SN_EXPORT_UINT32(crypto_pwhash_PASSWD_MIN, crypto_pwhash_PASSWD_MIN);
  SN_EXPORT_UINT32(crypto_pwhash_PASSWD_MAX, crypto_pwhash_PASSWD_MAX);
  SN_EXPORT_UINT32(crypto_pwhash_SALTBYTES, crypto_pwhash_SALTBYTES);
  SN_EXPORT_UINT32(crypto_pwhash_STRBYTES, crypto_pwhash_STRBYTES);
  SN_EXPORT_STRING(crypto_pwhash_STRPREFIX, crypto_pwhash_STRPREFIX);
  SN_EXPORT_UINT32(crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_OPSLIMIT_MIN);
  SN_EXPORT_UINT32(crypto_pwhash_OPSLIMIT_MAX, crypto_pwhash_OPSLIMIT_MAX);
  SN_EXPORT_UINT64(crypto_pwhash_MEMLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN);
  SN_EXPORT_UINT64(crypto_pwhash_MEMLIMIT_MAX, crypto_pwhash_MEMLIMIT_MAX);
  SN_EXPORT_UINT32(crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_OPSLIMIT_INTERACTIVE);
  SN_EXPORT_UINT64(crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE);
  SN_EXPORT_UINT32(crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_OPSLIMIT_MODERATE);
  SN_EXPORT_UINT64(crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE);
  SN_EXPORT_UINT32(crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_OPSLIMIT_SENSITIVE);
  SN_EXPORT_UINT64(crypto_pwhash_MEMLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE);
  SN_EXPORT_STRING(crypto_pwhash_PRIMITIVE, crypto_pwhash_PRIMITIVE);

  SN_EXPORT_FUNCTION_SCOPED("crypto_pwhash_scryptsalsa208sha256", sn_crypto_pwhash_scryptsalsa208sha256);
  SN_EXPORT_FUNCTION_SCOPED("crypto_pwhash_scryptsalsa208sha256_str", sn_crypto_pwhash_scryptsalsa208sha256_str);
  SN_EXPORT_FUNCTION_SCOPED("crypto_pwhash_scryptsalsa208sha256_str_verify", sn_crypto_pwhash_scryptsalsa208sha256_str_verify);
  SN_EXPORT_FUNCTION_SCOPED("crypto_pwhash_scryptsalsa208sha256_str_needs_rehash", sn_crypto_pwhash_scryptsalsa208sha256_str_needs_rehash);
  SN_EXPORT_FUNCTION(crypto_pwhash_scryptsalsa208sha256_async, sn_crypto_pwhash_scryptsalsa208sha256_async);
  SN_EXPORT_FUNCTION(crypto_pwhash_scryptsalsa208sha256_str_async, sn_crypto_pwhash_scryptsalsa208sha256_str_async)
  SN_EXPORT_FUNCTION(crypto_pwhash_scryptsalsa208sha256_str_verify_async, sn_crypto_pwhash_scryptsalsa208sha256_str_verify_async);
  SN_EXPORT_UINT64(crypto_pwhash_scryptsalsa208sha256_BYTES_MIN, crypto_pwhash_scryptsalsa208sha256_BYTES_MIN);
  SN_EXPORT_UINT64(crypto_pwhash_scryptsalsa208sha256_BYTES_MAX, crypto_pwhash_scryptsalsa208sha256_BYTES_MAX);
  SN_EXPORT_UINT64(crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN, crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN);
  SN_EXPORT_UINT64(crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX, crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX);
  SN_EXPORT_UINT64(crypto_pwhash_scryptsalsa208sha256_SALTBYTES, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
  SN_EXPORT_UINT64(crypto_pwhash_scryptsalsa208sha256_STRBYTES, crypto_pwhash_scryptsalsa208sha256_STRBYTES);
  SN_EXPORT_STRING(crypto_pwhash_scryptsalsa208sha256_STRPREFIX, crypto_pwhash_scryptsalsa208sha256_STRPREFIX);
  SN_EXPORT_UINT32(crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN, crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN);
  SN_EXPORT_UINT32(crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX, crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX);
  SN_EXPORT_UINT64(crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN, crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN);
  SN_EXPORT_UINT64(crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX, crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX);
  SN_EXPORT_UINT32(crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE, crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE);
  SN_EXPORT_UINT64(crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE, crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
  SN_EXPORT_UINT32(crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE);
  SN_EXPORT_UINT64(crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE, crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE);

  // crypto_scalarmult

  SN_EXPORT_FUNCTION_SCOPED("crypto_scalarmult_base", sn_crypto_scalarmult_base);
  SN_EXPORT_FUNCTION_SCOPED("crypto_scalarmult", sn_crypto_scalarmult);
  SN_EXPORT_STRING(crypto_scalarmult_PRIMITIVE, crypto_scalarmult_PRIMITIVE);
  SN_EXPORT_UINT32(crypto_scalarmult_BYTES, crypto_scalarmult_BYTES);
  SN_EXPORT_UINT32(crypto_scalarmult_SCALARBYTES, crypto_scalarmult_SCALARBYTES);

  SN_EXPORT_FUNCTION_SCOPED("crypto_scalarmult_ed25519_base", sn_crypto_scalarmult_ed25519_base);
  SN_EXPORT_FUNCTION_SCOPED("crypto_scalarmult_ed25519", sn_crypto_scalarmult_ed25519);
  SN_EXPORT_FUNCTION_SCOPED("crypto_scalarmult_ed25519_base_noclamp", sn_crypto_scalarmult_ed25519_base_noclamp);
  SN_EXPORT_FUNCTION_SCOPED("crypto_scalarmult_ed25519_noclamp", sn_crypto_scalarmult_ed25519_noclamp);
  SN_EXPORT_UINT32(crypto_scalarmult_ed25519_BYTES, crypto_scalarmult_ed25519_BYTES);
  SN_EXPORT_UINT32(crypto_scalarmult_ed25519_SCALARBYTES, crypto_scalarmult_ed25519_SCALARBYTES);

  // crypto_secretbox

  SN_EXPORT_FUNCTION_SCOPED("crypto_secretbox_easy", sn_crypto_secretbox_easy);
  SN_EXPORT_FUNCTION_SCOPED("crypto_secretbox_open_easy", sn_crypto_secretbox_open_easy);
  SN_EXPORT_FUNCTION_SCOPED("crypto_secretbox_detached", sn_crypto_secretbox_detached);
  SN_EXPORT_FUNCTION_SCOPED("crypto_secretbox_open_detached", sn_crypto_secretbox_open_detached);
  SN_EXPORT_UINT32(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
  SN_EXPORT_UINT32(crypto_secretbox_NONCEBYTES, crypto_secretbox_NONCEBYTES);
  SN_EXPORT_UINT32(crypto_secretbox_MACBYTES, crypto_secretbox_MACBYTES);
  SN_EXPORT_STRING(crypto_secretbox_PRIMITIVE, crypto_secretbox_PRIMITIVE);

  // crypto_secretstream

  SN_EXPORT_FUNCTION_NOSCOPE("crypto_secretstream_xchacha20poly1305_keygen", sn_crypto_secretstream_xchacha20poly1305_keygen);
  SN_EXPORT_FUNCTION_NOSCOPE("crypto_secretstream_xchacha20poly1305_init_push", sn_crypto_secretstream_xchacha20poly1305_init_push);
  SN_EXPORT_FUNCTION_NOSCOPE("crypto_secretstream_xchacha20poly1305_init_pull", sn_crypto_secretstream_xchacha20poly1305_init_pull);
  SN_EXPORT_FUNCTION_NOSCOPE("crypto_secretstream_xchacha20poly1305_push", sn_crypto_secretstream_xchacha20poly1305_push);
  SN_EXPORT_FUNCTION_NOSCOPE("crypto_secretstream_xchacha20poly1305_pull", sn_crypto_secretstream_xchacha20poly1305_pull);
  SN_EXPORT_FUNCTION_NOSCOPE("crypto_secretstream_xchacha20poly1305_rekey", sn_crypto_secretstream_xchacha20poly1305_rekey);

  SN_EXPORT_UINT32(crypto_secretstream_xchacha20poly1305_STATEBYTES, sizeof(crypto_secretstream_xchacha20poly1305_state));
  SN_EXPORT_UINT32(crypto_secretstream_xchacha20poly1305_ABYTES, crypto_secretstream_xchacha20poly1305_ABYTES);
  SN_EXPORT_UINT32(crypto_secretstream_xchacha20poly1305_HEADERBYTES, crypto_secretstream_xchacha20poly1305_HEADERBYTES);
  SN_EXPORT_UINT32(crypto_secretstream_xchacha20poly1305_KEYBYTES, crypto_secretstream_xchacha20poly1305_KEYBYTES);
  SN_EXPORT_UINT32(crypto_secretstream_xchacha20poly1305_TAGBYTES, 1);
  SN_EXPORT_UINT64(crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX, crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX);
  SN_EXPORT_UINT32(crypto_secretstream_xchacha20poly1305_TAG_MESSAGE, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
  SN_EXPORT_UINT32(crypto_secretstream_xchacha20poly1305_TAG_PUSH, crypto_secretstream_xchacha20poly1305_TAG_PUSH);
  SN_EXPORT_UINT32(crypto_secretstream_xchacha20poly1305_TAG_REKEY, crypto_secretstream_xchacha20poly1305_TAG_REKEY);
  SN_EXPORT_UINT32(crypto_secretstream_xchacha20poly1305_TAG_FINAL, crypto_secretstream_xchacha20poly1305_TAG_FINAL);

  // crypto_shorthash

  SN_EXPORT_FUNCTION_SCOPED("crypto_shorthash", sn_crypto_shorthash);
  SN_EXPORT_UINT32(crypto_shorthash_BYTES, crypto_shorthash_BYTES);
  SN_EXPORT_UINT32(crypto_shorthash_KEYBYTES, crypto_shorthash_KEYBYTES);
  SN_EXPORT_STRING(crypto_shorthash_PRIMITIVE, crypto_shorthash_PRIMITIVE);

  // crypto_sign

  SN_EXPORT_FUNCTION_SCOPED("crypto_sign_keypair", sn_crypto_sign_keypair);
  SN_EXPORT_FUNCTION_SCOPED("crypto_sign_seed_keypair", sn_crypto_sign_seed_keypair);
  SN_EXPORT_FUNCTION_SCOPED("crypto_sign", sn_crypto_sign);
  SN_EXPORT_FUNCTION_SCOPED("crypto_sign_open", sn_crypto_sign_open);
  SN_EXPORT_FUNCTION_SCOPED("crypto_sign_detached", sn_crypto_sign_detached);
  SN_EXPORT_FUNCTION_NOSCOPE("crypto_sign_verify_detached", sn_crypto_sign_verify_detached);
  SN_EXPORT_FUNCTION_SCOPED("crypto_sign_ed25519_sk_to_pk", sn_crypto_sign_ed25519_sk_to_pk);
  SN_EXPORT_FUNCTION_SCOPED("crypto_sign_ed25519_pk_to_curve25519", sn_crypto_sign_ed25519_pk_to_curve25519);
  SN_EXPORT_FUNCTION_SCOPED("crypto_sign_ed25519_sk_to_curve25519", sn_crypto_sign_ed25519_sk_to_curve25519);

  SN_EXPORT_UINT32(crypto_sign_SEEDBYTES, crypto_sign_SEEDBYTES);
  SN_EXPORT_UINT32(crypto_sign_PUBLICKEYBYTES, crypto_sign_PUBLICKEYBYTES);
  SN_EXPORT_UINT32(crypto_sign_SECRETKEYBYTES, crypto_sign_SECRETKEYBYTES);
  SN_EXPORT_UINT32(crypto_sign_BYTES, crypto_sign_BYTES);

  // crypto_stream

  SN_EXPORT_FUNCTION_SCOPED("crypto_stream", sn_crypto_stream);
  SN_EXPORT_UINT32(crypto_stream_KEYBYTES, crypto_stream_KEYBYTES);
  SN_EXPORT_UINT32(crypto_stream_NONCEBYTES, crypto_stream_NONCEBYTES);
  SN_EXPORT_STRING(crypto_stream_PRIMITIVE, crypto_stream_PRIMITIVE);

  SN_EXPORT_FUNCTION_NOSCOPE("crypto_stream_xor", sn_crypto_stream_xor);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_xor_init", sn_crypto_stream_xor_wrap_init);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_xor_update", sn_crypto_stream_xor_wrap_update);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_xor_final", sn_crypto_stream_xor_wrap_final);
  SN_EXPORT_UINT32(crypto_stream_xor_STATEBYTES, sizeof(sn_crypto_stream_xor_state));

  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_chacha20", sn_crypto_stream_chacha20);
  SN_EXPORT_UINT32(crypto_stream_chacha20_KEYBYTES, crypto_stream_chacha20_KEYBYTES);
  SN_EXPORT_UINT32(crypto_stream_chacha20_NONCEBYTES, crypto_stream_chacha20_NONCEBYTES);
  SN_EXPORT_UINT64(crypto_stream_chacha20_MESSAGEBYTES_MAX, crypto_stream_chacha20_MESSAGEBYTES_MAX);

  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_chacha20_xor", sn_crypto_stream_chacha20_xor);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_chacha20_xor_ic", sn_crypto_stream_chacha20_xor_ic);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_chacha20_xor_init", sn_crypto_stream_chacha20_xor_wrap_init);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_chacha20_xor_update", sn_crypto_stream_chacha20_xor_wrap_update);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_chacha20_xor_final", sn_crypto_stream_chacha20_xor_wrap_final);
  SN_EXPORT_UINT32(crypto_stream_chacha20_xor_STATEBYTES, sizeof(sn_crypto_stream_chacha20_xor_state));

  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_chacha20_ietf", sn_crypto_stream_chacha20_ietf);
  SN_EXPORT_UINT32(crypto_stream_chacha20_ietf_KEYBYTES, crypto_stream_chacha20_ietf_KEYBYTES);
  SN_EXPORT_UINT32(crypto_stream_chacha20_ietf_NONCEBYTES, crypto_stream_chacha20_ietf_NONCEBYTES);
  SN_EXPORT_UINT64(crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX, crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX);
  SN_EXPORT_UINT32(crypto_stream_chacha20_ietf_xor_STATEBYTES, sizeof(sn_crypto_stream_chacha20_ietf_xor_state));

  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_chacha20_ietf_xor", sn_crypto_stream_chacha20_ietf_xor);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_chacha20_ietf_xor_ic", sn_crypto_stream_chacha20_ietf_xor_ic);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_chacha20_ietf_xor_init", sn_crypto_stream_chacha20_ietf_xor_wrap_init);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_chacha20_ietf_xor_update", sn_crypto_stream_chacha20_ietf_xor_wrap_update);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_chacha20_ietf_xor_final", sn_crypto_stream_chacha20_ietf_xor_wrap_final);

  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_xchacha20", sn_crypto_stream_xchacha20);
  SN_EXPORT_UINT32(crypto_stream_xchacha20_KEYBYTES, crypto_stream_xchacha20_KEYBYTES);
  SN_EXPORT_UINT32(crypto_stream_xchacha20_NONCEBYTES, crypto_stream_xchacha20_NONCEBYTES);
  SN_EXPORT_UINT64(crypto_stream_xchacha20_MESSAGEBYTES_MAX, crypto_stream_xchacha20_MESSAGEBYTES_MAX);

  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_xchacha20_xor", sn_crypto_stream_xchacha20_xor);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_xchacha20_xor_ic", sn_crypto_stream_xchacha20_xor_ic);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_xchacha20_xor_init", sn_crypto_stream_xchacha20_xor_wrap_init);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_xchacha20_xor_update", sn_crypto_stream_xchacha20_xor_wrap_update);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_xchacha20_xor_final", sn_crypto_stream_xchacha20_xor_wrap_final);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_xchacha20", sn_crypto_stream_xchacha20);
  SN_EXPORT_UINT32(crypto_stream_xchacha20_xor_STATEBYTES, sizeof(sn_crypto_stream_xchacha20_xor_state));

  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_salsa20", sn_crypto_stream_salsa20);
  SN_EXPORT_UINT32(crypto_stream_salsa20_KEYBYTES, crypto_stream_salsa20_KEYBYTES);
  SN_EXPORT_UINT32(crypto_stream_salsa20_NONCEBYTES, crypto_stream_salsa20_NONCEBYTES);
  SN_EXPORT_UINT64(crypto_stream_salsa20_MESSAGEBYTES_MAX, crypto_stream_salsa20_MESSAGEBYTES_MAX);

  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_salsa20_xor", sn_crypto_stream_salsa20_xor);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_salsa20_xor_ic", sn_crypto_stream_salsa20_xor_ic);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_salsa20_xor_init", sn_crypto_stream_salsa20_xor_wrap_init);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_salsa20_xor_update", sn_crypto_stream_salsa20_xor_wrap_update);
  SN_EXPORT_FUNCTION_SCOPED("crypto_stream_salsa20_xor_final", sn_crypto_stream_salsa20_xor_wrap_final);
  SN_EXPORT_UINT32(crypto_stream_salsa20_xor_STATEBYTES, sizeof(sn_crypto_stream_salsa20_xor_state));

  // extensions

  // tweak

  SN_EXPORT_FUNCTION_SCOPED("extension_tweak_ed25519_base", sn_extension_tweak_ed25519_base);
  SN_EXPORT_FUNCTION_SCOPED("extension_tweak_ed25519_sign_detached", sn_extension_tweak_ed25519_sign_detached);
  SN_EXPORT_FUNCTION_SCOPED("extension_tweak_ed25519_sk_to_scalar", sn_extension_tweak_ed25519_sk_to_scalar);
  SN_EXPORT_FUNCTION_SCOPED("extension_tweak_ed25519_scalar", sn_extension_tweak_ed25519_scalar);
  SN_EXPORT_FUNCTION_SCOPED("extension_tweak_ed25519_pk", sn_extension_tweak_ed25519_pk);
  SN_EXPORT_FUNCTION_SCOPED("extension_tweak_ed25519_keypair", sn_extension_tweak_ed25519_keypair);
  SN_EXPORT_FUNCTION_SCOPED("extension_tweak_ed25519_scalar_add", sn_extension_tweak_ed25519_scalar_add);
  SN_EXPORT_FUNCTION_SCOPED("extension_tweak_ed25519_pk_add", sn_extension_tweak_ed25519_pk_add);
  SN_EXPORT_FUNCTION_SCOPED("extension_tweak_ed25519_keypair_add", sn_extension_tweak_ed25519_keypair_add);
  SN_EXPORT_UINT32(extension_tweak_ed25519_BYTES, sn__extension_tweak_ed25519_BYTES);
  SN_EXPORT_UINT32(extension_tweak_ed25519_SCALARBYTES, sn__extension_tweak_ed25519_SCALARBYTES);

  // pbkdf2

  SN_EXPORT_FUNCTION_SCOPED("extension_pbkdf2_sha512", sn_extension_pbkdf2_sha512);
  SN_EXPORT_FUNCTION(extension_pbkdf2_sha512_async, sn_extension_pbkdf2_sha512_async);
  SN_EXPORT_UINT32(extension_pbkdf2_sha512_SALTBYTES, sn__extension_pbkdf2_sha512_SALTBYTES);
  SN_EXPORT_UINT32(extension_pbkdf2_sha512_HASHBYTES, sn__extension_pbkdf2_sha512_HASHBYTES);
  SN_EXPORT_UINT32(extension_pbkdf2_sha512_ITERATIONS_MIN, sn__extension_pbkdf2_sha512_ITERATIONS_MIN);
  SN_EXPORT_UINT64(extension_pbkdf2_sha512_BYTES_MAX, sn__extension_pbkdf2_sha512_BYTES_MAX);

#undef SN_EXPORT_FUNCTION_SCOPED
#undef SN_EXPORT_FUNCTION_NOSCOPE

  return exports;
}

BARE_MODULE(sodium_native, sodium_native_exports)
