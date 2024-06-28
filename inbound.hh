#ifndef SNIPROXY_INBOUND_HH_
#define SNIPROXY_INBOUND_HH_
#include "thread_common.hh"

#include <filesystem>
struct inbound_parameter {
  thread_common_parameters     common_parameters;
  int                          pipe_to_next; // pipe to hand connection over to next stage
  const std::filesystem::path &ca_key_path;  // path to directory under which key of CA should be placed
};
void inbound(inbound_parameter arguments);
#endif