// backend server for the dashboard
//  note that this is far from a fully functional HTTP & WebSocket server, only a very limited subset
#ifndef SNIPROXY_BACKEND_HH_
#define SNIPROXY_BACKEND_HH_
#include "thread_common.hh"

#include <atomic>
extern std::atomic_uint64_t bytes_uploaded;
extern std::atomic_uint64_t bytes_downloaded;
struct backend_parameter {
  thread_common_parameters common_parameters;
};
void backend(backend_parameter arguments);
#endif