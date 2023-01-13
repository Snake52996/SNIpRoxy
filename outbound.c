#include "outbound.h"
#include "connection.h"
#include "dns_cache.h"
#include "thread_common.h"
#include <baSe/list.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/select.h>
#include <ares.h>
#include <stdio.h>
#include <arpa/nameser.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
struct callback_parameter{
    ListNode* hint;
    int hint_type;
    ListNode* attached_connection_node;
};
static int pipe_to_next;
static List outbound;
static struct dns_cache cache;
static bool loop = true;
void proceed_connection(const struct dns_cache_entry* entry, ListNode* connection_node){
    char readable_address_buffer[INET6_ADDRSTRLEN];
    inet_ntop(
        entry->ai_family,
        entry->ai_family == AF_INET ?
            (void*)&(((struct sockaddr_in*)entry->ai_addr)->sin_addr)
            : (void*)&(((struct sockaddr_in6*)entry->ai_addr)->sin6_addr),
        readable_address_buffer,
        INET6_ADDRSTRLEN
    );
    struct connecting_connection* c_connection = connection_node->data;
    struct established_connection* e_connection = toEstablishedConnection(c_connection);
    fprintf(stderr, "outbound: resolved for %s: %s\n", e_connection->local_keypair->hostname, readable_address_buffer);
    connection_node->data = e_connection;
    e_connection->remote_socket = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
    ssize_t rtv = connect(e_connection->remote_socket, entry->ai_addr, entry->ai_addrlen);
    if(rtv == 0 || (rtv == -1 && errno == EINPROGRESS)){
        List_detach(&outbound, connection_node);
        do{
            rtv = write(pipe_to_next, &connection_node, sizeof(ListNode*));
        }while(rtv == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
    }else{
        fprintf(stderr, "outbound: failed when connecting to %s: %s\n", e_connection->local_keypair->hostname, strerror(errno));
        List_erase(&outbound, connection_node);
    }
}
void callback(void *arg, int status, [[maybe_unused]] int timeouts, struct ares_addrinfo *result){
    struct callback_parameter* parameter = arg;
    ListNode* node = parameter->attached_connection_node;
    struct connecting_connection* c_connection = node->data;
    if(status == ARES_SUCCESS){
        struct dns_cache_entry* entry = dns_cache_insert(
            &cache, parameter->hint, parameter->hint_type,
            c_connection->local_keypair->hostname, result->nodes
        );
        ares_freeaddrinfo(result);
        proceed_connection(entry, node);
    }else{
        fprintf(
            stderr, "DNS failed for %s: %s\n", c_connection->local_keypair->hostname, ares_strerror(status));
    }
    free(arg);
}
static int rpc_fd;
static void handle_thread_call(){
    int call_id;
    read(rpc_fd, &call_id, sizeof(call_id));
    switch(call_id){
        case ThreadCallIDExit:
            loop = false;
            break;
        default: break;
    }
}
void* outbound_entry(void* arg){
    printf("outbound: starting\n");
    maskSignals();
    struct outbound_parameter* parameters = arg;
    rpc_fd = parameters->common_parameters.rpc_fd;
    pipe_to_next = parameters->pipe_to_next;
    List_initialize(&outbound);
    dns_cache_init(&cache, 64);
    fd_set rset;
    fd_set wset;
    struct in_addr addr = { .s_addr = inet_addr("127.0.0.1") };
    ares_channel channel;
    struct ares_options options = {
        .timeout = 8000,
        .servers = &addr,
        .nservers = 1,
        .lookups = "b",
    };
    FD_ZERO(&rset);
    FD_ZERO(&wset);
    struct ares_addrinfo_hints hints = {
        .ai_family = AF_UNSPEC,
        .ai_flags = ARES_AI_NOSORT,
        .ai_protocol = 0,
        .ai_socktype = SOCK_STREAM
    };
    ares_library_init(ARES_LIB_INIT_ALL);
    ares_init_options(&channel, &options, ARES_OPT_TIMEOUTMS | ARES_OPT_SERVERS | ARES_OPT_LOOKUPS);
    ListNode* node;
    ssize_t rtv;
    struct timeval tv;
    ListNode* hint;
    int hint_type;
    int fd_count_low_bound = (parameters->pipe_from_last > rpc_fd ? parameters->pipe_from_last : rpc_fd) + 1;
    while(loop){
        tv.tv_sec = 6;
        tv.tv_usec = 0;
        int fd_count = ares_fds(channel, &rset, &wset);
        FD_SET(parameters->pipe_from_last, &rset);
        FD_SET(rpc_fd, &rset);
        if(fd_count < fd_count_low_bound) fd_count = fd_count_low_bound;
        int count = select(fd_count, &rset, &wset, NULL, &tv);
        if(count == 0) continue;
        if(FD_ISSET(rpc_fd, &rset)){
            --count;
            handle_thread_call();
            FD_CLR(rpc_fd, &rset);
        }
        if(FD_ISSET(parameters->pipe_from_last, &rset)){
            count--;
            rtv = read(parameters->pipe_from_last, &node, sizeof(ListNode*));
            if(
                (rtv != sizeof(ListNode*) && rtv != -1)
                || (rtv == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
            ){
                fprintf(
                    stderr, "outbound: error reading from pipe after %ld bytes: %s\n",
                    rtv == -1 ? 0 : rtv, strerror(errno)
                );
                break;
            }
            if(rtv == sizeof(ListNode*)){
                List_emplace_back(&outbound, node);
                struct connecting_connection* c_connection = node->data;
                fprintf(stderr, "outbound: received connection to %s\n", c_connection->local_keypair->hostname);
                if(dns_cache_lookup(&cache, c_connection->local_keypair->hostname, &hint, &hint_type)){
                    proceed_connection(hint->data, node);
                }else{
                    struct callback_parameter* c_parameter = malloc(sizeof(struct callback_parameter));
                    c_parameter->attached_connection_node = node;
                    c_parameter->hint = hint;
                    c_parameter->hint_type = hint_type;
                    ares_getaddrinfo(
                        channel,
                        c_connection->local_keypair->hostname,
                        "https", &hints, callback, c_parameter
                    );
                }
            }
            FD_CLR(parameters->pipe_from_last, &rset);
        }
        if(count == 0) continue;
        ares_process(channel, &rset, &wset);
    }
    ares_destroy(channel);
    ares_library_cleanup();
    List_clear(&outbound);
    dns_cache_clear(&cache);
    close(pipe_to_next);
    close(parameters->pipe_from_last);
    close(rpc_fd);
    printf("outbound: exiting\n");
    pthread_exit(NULL);
}