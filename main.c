#include "common.h"
#include "inbound.h"
#include "outbound.h"
#include "server.h"
#include "thread_common.h"
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct thread_control_block {
  pthread_t handle;
  int rpc_fd;
};
static size_t thread_count;
static struct thread_control_block *threads;
void signal_handler(int signal) {
  int call_id = ThreadCallIDExit;
  if (signal == SIGINT) {
    for (size_t i = 0; i < thread_count; i++) {
      write(threads[i].rpc_fd, &call_id, sizeof(call_id));
    }
  }
}
int main() {
  fprintf(stderr, "launching SNIProxy...\n");
  CHECK(gnutls_global_init());
  thread_count = 3;
  threads = malloc(sizeof(struct thread_control_block) * thread_count);
  int pipe_buffer[2];
  struct inbound_parameter inbound_parameter;
  struct outbound_parameter outbound_parameter;
  struct server_parameter server_parameter;
  pipe(pipe_buffer);
  inbound_parameter.common_parameters.rpc_fd = pipe_buffer[0];
  threads[0].rpc_fd = pipe_buffer[1];
  pipe(pipe_buffer);
  inbound_parameter.pipe_to_next = pipe_buffer[1];
  outbound_parameter.pipe_from_last = pipe_buffer[0];
  pipe(pipe_buffer);
  outbound_parameter.common_parameters.rpc_fd = pipe_buffer[0];
  threads[1].rpc_fd = pipe_buffer[1];
  pipe(pipe_buffer);
  outbound_parameter.pipe_to_next = pipe_buffer[1];
  server_parameter.pipe_from_last = pipe_buffer[0];
  pipe(pipe_buffer);
  server_parameter.common_parameters.rpc_fd = pipe_buffer[0];
  threads[2].rpc_fd = pipe_buffer[1];
  pthread_create(&threads[0].handle, NULL, inbound_entry, &inbound_parameter);
  pthread_create(&threads[1].handle, NULL, outbound_entry, &outbound_parameter);
  pthread_create(&threads[2].handle, NULL, server_entry, &server_parameter);
  signal(SIGINT, signal_handler);
  for (size_t i = 0; i < thread_count; i++) {
    pthread_join(threads[i].handle, NULL);
    close(threads[i].rpc_fd);
  }
  free(threads);
  gnutls_global_deinit();
  return 0;
}