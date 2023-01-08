#ifndef SNIPROXY_INBOUND_H_
#define SNIPROXY_INBOUND_H_
struct inbound_parameter{
    int pipe_to_next;
};
void* inbound_entry(void* arg);
#endif