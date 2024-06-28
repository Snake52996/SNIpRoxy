#ifndef SNIPROXY_RESOLVE_HH_
#define SNIPROXY_RESOLVE_HH_
#include "thread_common.hh"

#include <filesystem>
struct resolve_parameter {
  struct thread_common_parameters common_parameters;
  int                             pipe_from_last;
  int                             pipe_to_next;
  std::filesystem::path           pinned_dns_cache;
};
void resolve(resolve_parameter arguments);
#endif