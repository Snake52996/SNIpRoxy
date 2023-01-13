#ifndef SNIPROXY_THREAD_COMMON_H_
#define SNIPROXY_THREAD_COMMON_H_
enum ThreadCallID{
    ThreadCallIDExit,
};
struct thread_common_parameters{
    int rpc_fd;
};
void maskSignals();
#endif