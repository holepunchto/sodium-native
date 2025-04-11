#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include <js.h>
#include <jstl.h>
#include "typedcalls.h"
#include <sodium.h>

int32_t
sn_typed_crypto_generichash (
  // js_env_t env,
  js_receiver_t receiver,
  js_typedarray_t<uint8_t> out,
  js_typedarray_t<uint8_t> in,
  js_typedarray_t<uint8_t> key
) {
  // Question: can we js_throw_error() ?
  if (out.len < crypto_generichash_BYTES_MIN) return -1;
  if (out.len > crypto_generichash_BYTES_MAX) return -1;

  if (key.len) {
    if (key.len < crypto_generichash_KEYBYTES_MIN) return -1;
    if (key.len > crypto_generichash_KEYBYTES_MAX) return -1;
  }

  return crypto_generichash(out.data, out.len, in.data, in.len, key.data, key.len);
}

void register_typed_callbacks(js_env_t *env, js_value_t *exports) {
  int err;
  printf("typed callbacks registered\n");
  js_value_t *fn;
  err = js_create_typed_function<
    sn_typed_crypto_generichash,
    uint32_t,
    // js_env_t *,
    js_receiver_t,
    js_typedarray_t<uint8_t>,
    js_typedarray_t<uint8_t>,
    js_typedarray_t<uint8_t>
  >(env, "sn_typed_crypto_generichash", &fn);
  assert(err == 0);

  // will overwrite existing property during test
  err = js_set_named_property(env, exports, "sn_typed_crypto_generichash", fn);
  assert(err == 0);
}
