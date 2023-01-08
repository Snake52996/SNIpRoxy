#include "outbound.h"
#define _GNU_SOURCE
#include "common.h"
#include "inbound.h"
#include "outbound.h"
#include "server.h"
#include <gnutls/gnutls.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
int main(){
    fprintf(stderr, "launching SNIProxy...\n");
    CHECK(gnutls_global_init());
    int pipe_buffer[2];
    struct inbound_parameter inbound_parameter;
    struct outbound_parameter outbound_parameter;
    struct server_parameter server_parameter;
    pipe2(pipe_buffer, O_NONBLOCK);
    inbound_parameter.pipe_to_next = pipe_buffer[1];
    outbound_parameter.pipe_from_last = pipe_buffer[0];
    pipe2(pipe_buffer, O_NONBLOCK);
    outbound_parameter.pipe_to_next = pipe_buffer[1];
    server_parameter.pipe_from_last = pipe_buffer[0];
    pthread_t inbound_thread;
    pthread_t outbound_thread;
    pthread_t server_thread;
    pthread_create(&inbound_thread, NULL, inbound_entry, &inbound_parameter);
    pthread_create(&outbound_thread, NULL, outbound_entry, &outbound_parameter);
    pthread_create(&server_thread, NULL, server_entry, &server_parameter);
    pthread_join(inbound_thread, NULL);
    pthread_join(outbound_thread, NULL);
    pthread_join(server_thread, NULL);
    return 0;
}