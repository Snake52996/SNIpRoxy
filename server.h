#ifndef SNIPROXY_SERVER_H_
#define SNIPROXY_SERVER_H_
struct server_parameter{
    int pipe_from_last;
};
void* server_entry(void* arg);
#endif