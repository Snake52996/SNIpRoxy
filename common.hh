#ifndef SNIPROXY_COMMON_HH_
#define SNIPROXY_COMMON_HH_
#include <logpp.hh>

#include <ares.h>
#include <cerrno>
#include <gnutls/gnutls.h>
#include <stdlib.h>

// invoke gnutls call, then execute code in different branch according to return value
//  return value may be accessed as return_value
//  name of the API call is available as api_name
#define check_gnutls_call(succeed, failed, failed_fatally, API, ...)                                         \
  do {                                                                                                       \
    int         return_value = (API)(__VA_ARGS__);                                                           \
    const char *api_name     = #API;                                                                         \
    if (return_value == GNUTLS_E_SUCCESS) {                                                                  \
      succeed                                                                                                \
    } else if (gnutls_error_is_fatal(return_value)) {                                                        \
      failed_fatally                                                                                         \
    } else {                                                                                                 \
      failed                                                                                                 \
    }                                                                                                        \
  } while (false)

// assert successful API call to GNUTLS, any failed call will generate a critical logging line before
//  terminating the whole process. the return value of such call is stored to return_value
#define assert_gnutls_call_return_value(return_value, API, ...)                                              \
  do {                                                                                                       \
    (return_value) = (API)(__VA_ARGS__);                                                                     \
    if ((return_value) < 0) {                                                                                \
      LogPP::logger.critical(                                                                                \
        "GNUTLS call " #API " on " __FILE__ ":{} failed: {}", __LINE__, gnutls_strerror(return_value)        \
      );                                                                                                     \
      ::exit(EXIT_FAILURE);                                                                                  \
    }                                                                                                        \
  } while (false)
// assert successful API call to GNUTLS, any failed call will generate a critical logging line before
//  terminating the whole process
#define assert_gnutls_call(API, ...)                                                                         \
  do {                                                                                                       \
    int return_value;                                                                                        \
    assert_gnutls_call_return_value(return_value, API __VA_OPT__(, ) __VA_ARGS__);                           \
  } while (false)

// invoke syscall call, then execute code in different branch according to return value
//  name of the API call is available as api_name
#define check_syscall(succeed, failed, API, ...)                                                             \
  do {                                                                                                       \
    int         return_value = (API)(__VA_ARGS__);                                                           \
    const char *api_name     = #API;                                                                         \
    if (return_value != -1) {                                                                                \
      succeed                                                                                                \
    } else {                                                                                                 \
      failed                                                                                                 \
    }                                                                                                        \
  } while (false)

// assert successful linux syscall, any failed call, indicated by return value of -1,  will generate a
//  critical logging line before terminating the whole process. the return value of such call is stored to
//  return_value
#define assert_syscall_return_value(return_value, name, ...)                                                 \
  do {                                                                                                       \
    (return_value) = (name)(__VA_ARGS__);                                                                    \
    if ((return_value) == -1) {                                                                              \
      LogPP::logger.critical("syscall " #name " on " __FILE__ ":{} failed: {}", __LINE__, strerror(errno));  \
      ::exit(EXIT_FAILURE);                                                                                  \
    }                                                                                                        \
  } while (false)
// assert successful linux syscall, any failed call, indicated by return value of -1,  will generate a
//  critical logging line before terminating the whole process
#define assert_syscall(name, ...)                                                                            \
  do {                                                                                                       \
    int return_value;                                                                                        \
    assert_syscall_return_value(return_value, name __VA_OPT__(, ) __VA_ARGS__);                              \
  } while (false)

// this is required since according to the document, ares_library_init returns 0 on success
//  yet other functions returns ARES_SUCCESS
static_assert(ARES_SUCCESS == 0);
// invoke a ares call, then execute code in different branch according to return value
//  name of the API call is available as api_name
#define check_ares_call(succeed, failed, API, ...)                                                           \
  do {                                                                                                       \
    int         return_value = (API)(__VA_ARGS__);                                                           \
    const char *api_name     = #API;                                                                         \
    if (return_value == ARES_SUCCESS) {                                                                      \
      succeed                                                                                                \
    } else {                                                                                                 \
      failed                                                                                                 \
    }                                                                                                        \
  } while (false)

// assert successful ares call, any failed call will generate a critical logging line before terminating the
// whole process
#define assert_ares_call(name, ...)                                                                          \
  check_ares_call(                                                                                           \
    ,                                                                                                        \
    LogPP::logger.critical(                                                                                  \
      "ares call " #name " on " __FILE__ ":{} failed: {}", __LINE__, ares_strerror(return_value)             \
    );                                                                                                       \
    ::exit(EXIT_FAILURE);                                                                                    \
    , name __VA_OPT__(, ) __VA_ARGS__                                                                        \
  )

// shared subsystem loggers
struct loggers {
  const LogPP::Logger *performance_logger;
  const LogPP::Logger *transport_logger;
};
// globally accessible subsystem loggers, defined and initialized in main.cc
extern loggers *global_loggers;

// epoll helpers
inline uint64_t iterator_to_u64(std::bidirectional_iterator auto iterator) {
  static_assert(std::is_trivially_copyable_v<decltype(iterator)>);
  static_assert(sizeof(decltype(iterator)) == sizeof(uint64_t));
  return *reinterpret_cast<uint64_t *>(&iterator);
}
template <typename T> inline T u64_to_iterator(uint64_t value) {
  static_assert(std::is_trivially_copyable_v<T>);
  static_assert(sizeof(T) == sizeof(uint64_t));
  T result;
  *reinterpret_cast<uint64_t *>(&result) = value;
  return result;
}
#endif