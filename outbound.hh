#ifndef SNIPROXY_OUTBOUND_HH_
#define SNIPROXY_OUTBOUND_HH_
#include "thread_common.hh"

struct outbound_parameter {
  thread_common_parameters common_parameters;
  int                      pipe_from_last; // pipe to receive connections from last stage
  int                      pipe_to_next;   // pipe to hand connection over to next stage
};
void outbound(outbound_parameter arguments);
#endif