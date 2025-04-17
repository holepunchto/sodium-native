/**
 * Re-implementation of macros.h to ease port to fastcalls
 */
#include <assert.h>
#include <js.h>

#define SN_EXPORT_TYPED_FUNCTION(name, fn) \
  { \
    int err = js_set_property<fn>(env, exports, name); \
    assert(err == 0); \
  }

#define SN_ARG_OPT(name, use) \
  uint8_t *name##_data = NULL; \
  size_t name##_size = 0; \
  if (use) { \
    int err = js_get_typedarray_info(env, name, name##_data, name##_size); \
    assert(err == 0); \
  }

#define SN_ARG(name) \
  uint8_t *name##_data; \
  size_t name##_size; \
  { \
    int err = js_get_typedarray_info(env, name, name##_data, name##_size); \
    assert(err == 0); \
  }

#define SN_ARG_CAST(type, name, buffer) \
  type *name; \
  { \
    int err = js_get_typedarray_info<type>(env, buffer, name); \
    assert(err == 0); \
  }

#define SN_ARG_ISSET(name, bool_result) \
  { \
    js_value_type_t type; \
    int err = js_typeof(env, key, &type); \
    assert(err == 0); \
    bool_result = type != js_null && type != js_undefined; \
  }


// void returns
#define SN_THROW(condition, message, ...) \
  if ((condition)) { \
    int err = js_throw_error(env, NULL, message); \
    assert(err == 0); \
    return __VA_ARGS__; \
  }

#define SN_THROW_STATUS(status, callback_name, ...) \
  SN_THROW((status) != 0, "\"" #callback_name "\" failed", __VA_ARGS__)

#define SN_THROW_LEN(name, constant, ...) \
  SN_THROW(name##_size != constant, #name " must be " #constant " bytes long", __VA_ARGS__)

#define SN_THROW_MIN(name, constant, ...) \
  SN_THROW(name##_size < constant, #name " must be at least " #constant " bytes long", __VA_ARGS__)

#define SN_THROW_MAX(name, constant, ...) \
  SN_THROW(name##_size > constant, #name " must be at most " #constant " bytes long", __VA_ARGS__)

#define SN_THROW_BOUNDS(name, prefix, ...) \
  SN_THROW_MIN(name, prefix##_MIN, __VA_ARGS__) \
  SN_THROW_MAX(name, prefix##_MAX, __VA_ARGS__)


// boolean returns
#define SN_BOOLTHROW(condition, message) \
  SN_THROW(condition, message, false)

#define SN_BOOLTHROW_STATUS(status, callback_name) \
  SN_THROW(status, callback_name, false)

#define SN_BOOLTHROW_LEN(name, constant) \
  SN_THROW_LEN(name, constant, false)

#define SN_BOOLTHROW_MIN(name, constant) \
  SN_THROW_MIN(name, constant, false)

#define SN_BOOLTHROW_MAX(name, constant) \
  SN_THROW_MAX(name, constant, false)

#define SN_BOOLTHROW_BOUNDS(name, prefix) \
  SN_THROW_BOUNDS(name, prefix, false)

// int & uint returns
#define SN_INTTHROW(condition, message) \
  SN_THROW(condition, message, -1)

#define SN_INTTHROW_STATUS(status, callback_name) \
  SN_THROW(status, callback_name, -1)

#define SN_INTTHROW_LEN(name, constant) \
  SN_THROW_LEN(name, constant, -1)

#define SN_INTTHROW_MIN(name, constant) \
  SN_THROW_MIN(name, constant, -1)

#define SN_INTTHROW_MAX(name, constant) \
  SN_THROW_MAX(name, constant, -1)

#define SN_INTTHROW_BOUNDS(name, prefix) \
  SN_THROW_BOUNDS(name, prefix, -1)
