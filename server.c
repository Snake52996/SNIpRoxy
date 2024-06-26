#include "server.h"
#include "connection.h"
#include "thread_common.h"
#include <baSe/list.h>
#include <errno.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#define gnutlsCall(call, rtv, msg)                                                                           \
  do {                                                                                                       \
    if (((rtv) = (call)) < 0) {                                                                              \
      fprintf(stderr, "%s: %s\n", (msg), gnutls_strerror(rtv));                                              \
      exit(EXIT_FAILURE);                                                                                    \
    }                                                                                                        \
  } while (0)
#define LOOP_CHECK(rval, cmd)                                                                                \
  do {                                                                                                       \
    rval = cmd;                                                                                              \
  } while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)
static const char *DefaultPriorityString =
  "NONE:+VERS-TLS1.3:+COMP-ALL:+AEAD:+CTYPE-X509:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305"
  ":+GROUP-SECP256R1:+GROUP-SECP384R1:+GROUP-SECP521R1:+GROUP-X25519:+SIGN-RSA-PSS-RSAE-SHA256"
  ":+SIGN-RSA-PSS-RSAE-SHA384:+SIGN-RSA-PSS-RSAE-SHA512:+SIGN-EdDSA-Ed25519:%PROFILE_MEDIUM";
static bool loop = true;
static bool doHandshake(void *data, struct established_connection *e_connection, int epfd) {
  int rtv;
  do {
    rtv = gnutls_handshake(e_connection->remote_session);
    fprintf(stderr, "server: DEBUG: handshake return value = %d\n", rtv);
  } while (rtv < 0 && gnutls_error_is_fatal(rtv) == 0);
  if (rtv >= 0) {
    e_connection->status = ConnectionStatusEstablished;
    struct epoll_event ev;
    ev.events   = EPOLLERR | EPOLLIN;
    ev.data.ptr = (void *)((uintmax_t)data | 1);
    epoll_ctl(epfd, EPOLL_CTL_ADD, e_connection->local_socket, &ev);
  } else if (gnutls_error_is_fatal(rtv) != 0) {
    fprintf(stderr, "server: handshake error: %s\n", gnutls_strerror(rtv));
    return true;
  }
  return false;
}
static bool initializeHandshake(
  void *data, struct established_connection *e_connection, gnutls_certificate_credentials_t xcred, int epfd
) {
  int flags = fcntl(e_connection->remote_socket, F_GETFL);
  flags ^= O_NONBLOCK;
  fcntl(e_connection->remote_socket, F_SETFL, flags);
  struct epoll_event ev;
  ev.events   = EPOLLERR | EPOLLIN;
  ev.data.ptr = data;
  epoll_ctl(epfd, EPOLL_CTL_MOD, e_connection->remote_socket, &ev);
  do {
    if (gnutls_init(&e_connection->remote_session, GNUTLS_CLIENT | GNUTLS_NO_AUTO_SEND_TICKET | GNUTLS_AUTO_REAUTH | GNUTLS_POST_HANDSHAKE_AUTH | GNUTLS_NONBLOCK) < 0)
      break;
    if (gnutls_priority_set_direct(e_connection->remote_session, DefaultPriorityString, NULL) < 0)
      break;
    if (gnutls_credentials_set(e_connection->remote_session, GNUTLS_CRD_CERTIFICATE, xcred) < 0)
      break;
    gnutls_session_set_verify_cert(e_connection->remote_session, e_connection->local_keypair->hostname, 0);
    gnutls_handshake_set_timeout(e_connection->remote_session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
    gnutls_transport_set_int(e_connection->remote_session, e_connection->remote_socket);
    e_connection->status = ConnectionStatusRemoteHandshake;
    if (doHandshake(data, e_connection, epfd))
      break;
    return false;
  } while (false);
  return true;
}
static bool receiveConnection(List *list, int receive_fd, int epfd) {
  struct epoll_event ev;
  ev.events = EPOLLERR | EPOLLOUT;
  ssize_t   read_count;
  ListNode *node;
  read_count = read(receive_fd, &node, sizeof(ListNode *));
  if (read_count != sizeof(ListNode *))
    return true;
  fprintf(stderr, "server: connection received\n");
  List_emplace_back(list, node);
  ev.data.ptr = node;
  epoll_ctl(epfd, EPOLL_CTL_ADD, ((struct established_connection *)node->data)->remote_socket, &ev);
}
static int  rpc_fd;
static void handle_thread_call() {
  int call_id;
  read(rpc_fd, &call_id, sizeof(call_id));
  switch (call_id) {
  case ThreadCallIDExit:
    loop = false;
    break;
  default:
    break;
  }
}
void *server_entry(void *arg) {
  printf("server: starting\n");
  maskSignals();
  int rtv;
  enum { EpollEvents = 32, BufferSize = 0x10000 };
  struct server_parameter *parameters = arg;
  rpc_fd                              = parameters->common_parameters.rpc_fd;
  List established;
  List disconnecting;
  List_initialize(&established);
  List_initialize(&disconnecting);
  gnutls_certificate_credentials_t xcred;
  gnutlsCall(gnutls_certificate_allocate_credentials(&xcred), rtv, "allocate for certificate");
  gnutlsCall(gnutls_certificate_set_x509_system_trust(xcred), rtv, "load default certificate");
  int                epfd = epoll_create1(0);
  struct epoll_event ev, events[EpollEvents];
  ev.events  = EPOLLHUP | EPOLLERR | EPOLLIN;
  ev.data.fd = parameters->pipe_from_last;
  epoll_ctl(epfd, EPOLL_CTL_ADD, parameters->pipe_from_last, &ev);
  ev.events  = EPOLLIN;
  ev.data.fd = rpc_fd;
  epoll_ctl(epfd, EPOLL_CTL_ADD, rpc_fd, &ev);
  char    buffer[BufferSize];
  ssize_t read_size;
  while (loop) {
    int fds = epoll_wait(epfd, events, EpollEvents, -1);
    for (int i = 0; i < fds; i++) {
      if (events[i].data.fd == rpc_fd) {
        handle_thread_call();
        continue;
      }
      if (events[i].data.fd == parameters->pipe_from_last) {
        receiveConnection(&established, parameters->pipe_from_last, epfd);
        continue;
      }
      if (events[i].events & EPOLLOUT) {
        initializeHandshake(events[i].data.ptr, ((ListNode *)events[i].data.ptr)->data, xcred, epfd);
        continue;
      }
      ListNode                      *node         = (ListNode *)(((uintmax_t)events[i].data.ptr | 1) - 1);
      struct established_connection *e_connection = node->data;
      if (e_connection->status == ConnectionStatusDisconnecting)
        continue;
      if (events[i].events & EPOLLERR) {
        List_detach(&established, node);
        List_emplace_back(&disconnecting, node);
        e_connection->status = ConnectionStatusDisconnecting;
        continue;
      }
      if (events[i].events & EPOLLIN) {
        if (e_connection->status == ConnectionStatusConnecting) {
          if (initializeHandshake(node, e_connection, xcred, epfd)) {
            List_detach(&established, node);
            List_emplace_back(&disconnecting, node);
            e_connection->status = ConnectionStatusDisconnecting;
          }
        } else if (e_connection->status == ConnectionStatusRemoteHandshake) {
          if (doHandshake(node, e_connection, epfd)) {
            List_detach(&established, node);
            List_emplace_back(&disconnecting, node);
            e_connection->status = ConnectionStatusDisconnecting;
          }
        } else if (e_connection->status == ConnectionStatusEstablished) {
          if ((uintmax_t)events[i].data.ptr & 1) {
            LOOP_CHECK(read_size, gnutls_record_recv(e_connection->local_session, buffer, BufferSize));
            if (read_size <= 0) {
              List_detach(&established, node);
              List_emplace_back(&disconnecting, node);
              e_connection->status = ConnectionStatusDisconnecting;
              continue;
            }
            fprintf(stderr, "server: %ld bytes from local session\n", read_size);
            LOOP_CHECK(rtv, gnutls_record_send(e_connection->remote_session, buffer, read_size));
            if (rtv <= 0) {
              List_detach(&established, node);
              List_emplace_back(&disconnecting, node);
              e_connection->status = ConnectionStatusDisconnecting;
              continue;
            }
          } else {
            LOOP_CHECK(read_size, gnutls_record_recv(e_connection->remote_session, buffer, BufferSize));
            if (read_size <= 0) {
              List_detach(&established, node);
              List_emplace_back(&disconnecting, node);
              e_connection->status = ConnectionStatusDisconnecting;
              continue;
            }
            fprintf(stderr, "server: %ld bytes from remote session\n", read_size);
            LOOP_CHECK(rtv, gnutls_record_send(e_connection->local_session, buffer, read_size));
            if (rtv <= 0) {
              List_detach(&established, node);
              List_emplace_back(&disconnecting, node);
              e_connection->status = ConnectionStatusDisconnecting;
              continue;
            }
          }
        }
      }
    }
    List_clear(&disconnecting);
  }
  close(rpc_fd);
  close(epfd);
  List_clear(&established);
  gnutls_certificate_free_credentials(xcred);
  printf("server: exiting\n");
  pthread_exit(NULL);
}