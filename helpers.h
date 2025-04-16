/**
 * templates an minimal macros for jstl-fastcalls
 */
#include <assert.h>
#include <js.h>
#include <jstl.h>

template <auto fn>
struct sn_function_t;

template <typename R, typename... A, R(*impl)(js_env_t *, js_receiver_t, A...)>
struct sn_function_t<impl> {
  inline auto
  export_named (js_env_t *env, js_value_t *exports, const std::string &name) {
    js_function_t<R, js_receiver_t, A...> js_fn;

    int err = js_create_function<impl>(env, name, js_fn);
    assert(err == 0);

    err = js_set_named_property(env, exports, name.c_str(), js_fn.value);
    assert(err == 0);
  }
};

struct sn_error_t {
  std::string message;

  inline sn_error_t (const std::string &msg)
    : message(msg) { };

  inline void
  rethrow_js (js_env_t *env) const {
    int err = js_throw_error(env, nullptr, message.c_str());
    assert(err == 0);
  }
};

template <typename E>
struct sn_argument_t {
  js_env_t *env;

  js_typedarray_t<E> &buffer;

  const char* name;

  std::span<E> view;

  bool optional = false;

  bool present = false;

  inline sn_argument_t
  (js_env_t *e, js_typedarray_t<E> &b, const char *n, bool o)
  : env(e), buffer(b), name(n), optional(o) { }

  inline sn_argument_t &
  info () {
    int err;

    if (optional) {
      /* FIXME: bad include/defition
      js_value_type_t type;

      err = js_typeof(env, buffer.value, &type)
      assert(err == 0);

      present = type != js_undefined && type != js_null;
      */
      bool x;
      err = js_is_undefined(env, buffer, &x);
      assert(err == 0);

      if (!x) {
        err = js_is_null(env, buffer, &x);
        assert(err == 0);
      }

      present = !x;

      if (!present) return *this; // abort loading
    }

    err = js_get_typedarray_info(env, buffer, view);
    assert(err == 0);

    return *this;
  }

  inline sn_argument_t &
  min(size_t n, const char *constant) {
    if (optional && !present) return *this;

    bool invalid = view.size_bytes() < n;

    if (invalid) {
      throw sn_error_t(std::string(name) + " must be at least " + constant + " bytes");
    }

    return *this;
  }

  inline sn_argument_t &
  max(size_t n, const char *constant) {
    if (optional && !present) return *this;

    bool invalid = view.size_bytes() > n;

    if (invalid) {
      throw sn_error_t(std::string(name) + " must be at most \"" + constant + "\" bytes");
    }

    return *this;
  }

  inline sn_argument_t &
  length_equals(size_t n, const char *constant) {
    if (optional && !present) return *this;

    bool valid = view.size_bytes() == n;

    if (!valid) {
      throw sn_error_t(std::string(name) + " must equal  \"" + constant + "\" bytes");
    }

    return *this;
  }

  template <typename T>
  inline T *
  cast() {
    bool valid = view.size_bytes() == sizeof(T);

    if (!valid) {
      throw sn_error_t(std::string(name) + " must equal \"" + std::to_string(sizeof(T)) + "\" bytes");
    }

    return reinterpret_cast<T *>(view.data());
  }

  inline std::tuple<uint8_t *, size_t>
  unwrap() {
    if (optional && !present) return { nullptr, 0 };

    return { view.data(), view.size_bytes() };
  }
};

template <typename E>
constexpr sn_argument_t<E>
sn_arg(js_env_t *env, js_typedarray_t<E> &typedarray, const char *name, bool optional) {
  return sn_argument_t<E>(env, typedarray, name, optional);
}

#define SN_ARG(name, ...) \
  auto [name##_data, name##_size] = sn_arg(env, name, #name, false) \
  .info() \
  __VA_ARGS__ \
  .unwrap();

#define SN_ARG_OPT(name, ...) \
  auto [name##_data, name##_size] = sn_arg(env, name, #name, true) \
  .info() \
  __VA_ARGS__ \
  .unwrap();

#define SN_ARG_CAST(type, name, buffer) \
  auto name = sn_arg(env, buffer, #name, true) \
  .info() \
  .cast<type>();

#define SN_ARG_MIN(constant) \
  .min(constant, #constant)

#define SN_ARG_MAX(constant) \
  .max(constant, #constant)

#define SN_ARG_LEN(constant) \
  .length_equals(constant, #constant)

#define SN_ARG_BOUNDS(prefix) \
  SN_ARG_MIN(prefix##_MIN) \
  SN_ARG_MAX(prefix##_MAX)

#define SN_THROW(condition, message) \
  if ((condition)) throw sn_error_t(message);

#define SN_CATCH \
  catch (const sn_error_t &err) { \
    err.rethrow_js(env); \
  }

#define SN_EXPORT_TYPED_FUNCTION(name, fn) \
  sn_function_t<fn>().export_named(env, exports, name);
