#ifndef SNIPROXY_THREAD_COMMON_HH_
#define SNIPROXY_THREAD_COMMON_HH_
#include "common.hh"
enum class ThreadCallID {
  ThreadCallIDExit,       // terminate this thread normally
  ThreadCallIDReload,     // reload configurations (if any)
  ThreadCallIDClearCache, // clear cache (if any)
  ThreadCallIDSummary,    // show summary
};
struct thread_common_parameters {
  int            rpc_fd;  // file descriptor to receive thread calls
  const loggers &loggers; // shared loggers for subsystem debugging
};
void mask_signals();
#endif