#ifndef SNIPROXY_OUTBOUND_H_
#define SNIPROXY_OUTBOUND_H_
#include "thread_common.h"
struct outbound_parameter {
  struct thread_common_parameters common_parameters;
  int pipe_from_last;
  int pipe_to_next;
};
void *outbound_entry(void *arg);
#endif