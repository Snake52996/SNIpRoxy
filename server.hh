#ifndef SNIPROXY_SERVER_HH_
#define SNIPROXY_SERVER_HH_
#include "thread_common.hh"
struct server_parameter {
  thread_common_parameters common_parameters;
  int                      pipe_from_last;
};
void server(server_parameter arguments);
#endif