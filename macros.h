#define NAPI_STATUS_THROWS(call, message) \
  if ((call) != napi_ok) { \
    napi_throw_error(env, NULL, message); \
    return NULL; \
  }

#define NAPI_THROWS(condition, message) \
  if ((condition)) { \
    napi_throw_error(env, NULL, message); \
    return NULL; \
  }

#define NAPI_TYPE_ASSERT(name, var, type, message) \
  napi_valuetype name##_valuetype; \
  NAPI_STATUS_THROWS(napi_typeof(env, var, &name##_valuetype), ""); \
  if (name##_valuetype != type) { \
    napi_throw_type_error(env, NULL, message); \
    return NULL; \
  }

#define NAPI_TYPEDARRAY_ASSERT(name, var, message) \
  bool name##_is_typedarray; \
  NAPI_STATUS_THROWS(napi_is_typedarray(env, var, &name##_is_typedarray), ""); \
  if (name##_is_typedarray != true) { \
    napi_throw_type_error(env, NULL, message); \
    return NULL; \
  }

#define NAPI_RANGE_THROWS(condition, message) \
  if (condition) { \
    napi_throw_range_error(env, NULL, message); \
    return NULL; \
  }

#define NAPI_ARGV(n, method_name) \
  napi_value argv[n]; \
  size_t argc = n; \
  NAPI_STATUS_THROWS(napi_get_cb_info(env, info, &argc, argv, NULL, NULL), ""); \
  if (argc < n) { \
    napi_throw_type_error(env, NULL, #method_name " requires at least " #n " argument(s)"); \
    return NULL; \
  }

#define NAPI_EXPORT_FUNCTION(name, cb) \
  { \
    napi_value name##_fn; \
    NAPI_STATUS_THROWS(napi_create_function(env, #name, NAPI_AUTO_LENGTH, cb, NULL, &name##_fn), "") \
    NAPI_STATUS_THROWS(napi_set_named_property(env, exports, #name, name##_fn), "") \
  }

#define NAPI_EXPORT_UINT32(name, num) \
  { \
    napi_value name##_num; \
    NAPI_STATUS_THROWS(napi_create_uint32(env, num, &name##_num), "") \
    NAPI_STATUS_THROWS(napi_set_named_property(env, exports, #name, name##_num), "") \
  }
