#ifndef SNIPROXY_THREAD_COMMON_HH_
#define SNIPROXY_THREAD_COMMON_HH_
#include "common.hh"
enum ThreadCallID {
  ThreadCallIDExit, // terminate this thread normally
};
struct thread_common_parameters {
  int            rpc_fd;  // file descriptor to receive thread calls
  const loggers &loggers; // shared loggers for subsystem debugging
};
void mask_signals();
#endif