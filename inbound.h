#ifndef SNIPROXY_INBOUND_H_
#define SNIPROXY_INBOUND_H_
#include "thread_common.h"
struct inbound_parameter{
    struct thread_common_parameters common_parameters;
    int pipe_to_next;
};
void* inbound_entry(void* arg);
#endif