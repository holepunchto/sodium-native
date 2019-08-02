#include <node_api.h>
#include <assert.h>
#include "macros.h"
#include <sodium.h>

napi_value sn_randombytes_random (napi_env env, napi_callback_info info) {
  napi_value result;

  assert(napi_create_uint32(env, randombytes_random(), &result) == napi_ok);
  return result;
}

napi_value sn_randombytes_uniform (napi_env env, napi_callback_info info) {
  NAPI_ARGV(1, randombytes_uniform);
  NAPI_TYPE_ASSERT(upper_bound, argv[0], napi_number, "upper_bound must be a Number");

  uint32_t upper_bound;
  assert(napi_get_value_uint32(env, argv[0], &upper_bound) == napi_ok);

  napi_value result;
  assert(napi_create_uint32(env, randombytes_uniform(upper_bound), &result) == napi_ok);
  return result;
}

napi_value create_sodium_native(napi_env env) {
  napi_value exports;
  assert(napi_create_object(env, &exports) == napi_ok);

  NAPI_EXPORT_FUNCTION(randombytes_uniform, sn_randombytes_uniform)
  NAPI_EXPORT_FUNCTION(randombytes_random, sn_randombytes_random)

  return exports;
}

static napi_value Init(napi_env env, napi_value exports) {
  return create_sodium_native(env);
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
