#ifndef SNIPROXY_SERVER_H_
#define SNIPROXY_SERVER_H_
#include "thread_common.h"
struct server_parameter{
    struct thread_common_parameters common_parameters;
    int pipe_from_last;
};
void* server_entry(void* arg);
#endif