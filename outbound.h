#ifndef SNIPROXY_OUTBOUND_H_
#define SNIPROXY_OUTBOUND_H_
struct outbound_parameter{
    int pipe_from_last;
    int pipe_to_next;
};
void* outbound_entry(void* arg);
#endif