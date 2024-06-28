#include "inbound.hh"
#include "common.hh"
#include "connection.hh"
#include "thread_common.hh"

#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <gnutls/gnutls.h>
#include <list>
#include <memory>
#include <netinet/in.h>
#include <ranges>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
// policy specification used by local server, generally speaking we enable only very secure algorithms
static const char    *DefaultPriorityString = "SECURE192:-VERS-ALL:+VERS-TLS1.2:+VERS-TLS1.3";
// global logger for inbound subsystem
static LogPP::Logger *logger                = nullptr;
// shared subsystem loggers
static loggers       *loggers               = nullptr;

static std::list<std::unique_ptr<Connection>> inbound_connections;
static KeyManager                            *key_manager;

// if the server should keep running
static bool loop = true;

// callback function used to retrieve certificate used in local TLS handshake
//  this callback actually read SNI section sent by local client, get a keypair from the key manager
//  on-the-fly and use that as the certificate
static int certificate_callback(
  gnutls_session_t                              session,           // session requesting a certificate
  [[maybe_unused]] const gnutls_datum_t        *req_ca_rdn,        // not available in server side
  [[maybe_unused]] int                          nreqs,             // not available in server side
  [[maybe_unused]] const gnutls_pk_algorithm_t *sign_algos,        // not available in server side
  [[maybe_unused]] int                          sign_algos_length, // not available in server side
  gnutls_pcert_st                             **pcert,             // list of certificate to use
  unsigned int                                 *pcert_length,      // number of certificates in the list
  gnutls_privkey_t                             *pkey               // private keys, one for each certificate
) {
  // we need to find the Connection instance from the session supplied first
  Connection *connection = nullptr;
  for (auto &item : inbound_connections) {
    if (item->side[Connection::SideName::Local].session == session) {
      connection = item.get();
      break;
    }
  }
  if (connection == nullptr) {
    // this should not happen...
    logger->error("unexpected TLS session: no associated Connection instance found in list");
    return 1;
  }
  logger->trace("preparing certificate for connection " ConnectionIDFormatter, connection->identifier);
  int          return_value;
  unsigned int type;
  size_t       length = 0;

  // query name size first
  return_value = gnutls_server_name_get(session, nullptr, &length, &type, 0);
  if (return_value != GNUTLS_E_SHORT_MEMORY_BUFFER) {
    logger->error(
      "unexpected return value {} when querying SNI name length for connection " ConnectionIDFormatter
      ", if it is an error code, it reads {}",
      return_value,
      connection->identifier,
      gnutls_strerror(return_value)
    );
    // terminate handshake process
    return 1;
  }
  // make space
  std::string server_name(length, '\0');
  // query the actual name
  return_value = gnutls_server_name_get(session, server_name.data(), &length, &type, 0);
  if (return_value != GNUTLS_E_SUCCESS || type != GNUTLS_NAME_DNS) {
    logger->error(
      "failed to get server name for connection " ConnectionIDFormatter ": {}",
      connection->identifier,
      gnutls_strerror(return_value)
    );
    return 1;
  }
  // remove the last character which is a null-terminator written by GnuTLS which is not required
  server_name.pop_back();
  // get keypair from key manager and apply to session
  connection->key = std::move(key_manager->get_key_pair(server_name));
  *pcert          = &connection->key->cert;
  *pcert_length   = 1;
  *pkey           = connection->key->key;
  return 0;
}

static void summary() {
  std::string buffer = std::format(
    "\n====== begin summary ======\n  {} connection(s) in this stage:\n", inbound_connections.size()
  );
  for (const auto &connection : std::ranges::reverse_view(inbound_connections)) {
    buffer += std::format("    connection " ConnectionIDFormatter "\n", connection->identifier);
  }
  buffer += "======  end summary  ======\n";
  logger->information("{}", buffer);
}

// thread call handlers
static int  rpc_fd;
static void handle_thread_call() {
  ThreadCallID call_id;
  read(rpc_fd, &call_id, sizeof(call_id));
  switch (call_id) {
  case ThreadCallID::ThreadCallIDExit:
    loop = false;
    break;
  case ThreadCallID::ThreadCallIDReload:
    key_manager->reload();
    break;
  case ThreadCallID::ThreadCallIDClearCache:
    key_manager->clear();
    break;
  case ThreadCallID::ThreadCallIDSummary:
    summary();
    break;
  }
}

// entry of inbound
void inbound(inbound_parameter arguments) {
  // configure loggers
  auto logger_ = LogPP::logger.create_sub_logger("inbound");
  logger       = &logger_;

  auto performance_logger =
    arguments.common_parameters.loggers.performance_logger->create_sub_logger("inbound");
  struct loggers loggers_ {
    &performance_logger, nullptr
  };
  loggers = &loggers_;
  logger->information("starting...");

  logger->trace("masking signals...");
  mask_signals();
  logger->trace("signals masked");

  logger->trace("preparing remote thread call environment...");
  rpc_fd = arguments.common_parameters.rpc_fd;
  logger->trace("ready to handle remote thread calls");

  auto &key_manager_ = KeyManager::get_manager(arguments.ca_key_path);
  key_manager        = &key_manager_;

  logger->trace("setting up TLS certificate...");
  gnutls_certificate_credentials_t x509_cred;
  assert_gnutls_call(gnutls_certificate_allocate_credentials, &x509_cred);
  gnutls_certificate_set_retrieve_function2(x509_cred, certificate_callback);
  logger->trace("certificate getter ready...");

  logger->trace("setting up listening port...");
  // create a socket
  int listen_socket; // to be initialized on next line
  assert_syscall_return_value(listen_socket, socket, AF_INET, SOCK_STREAM, 0);
  set_nonblock(listen_socket);
  // hardcode server address as 127.0.0.1(localhost)
  sockaddr_in server_address;
  memset(&server_address, '\0', sizeof(server_address));
  server_address.sin_family      = AF_INET;
  server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
#ifdef USING_SANITIZER
  // if sanitize is used, listen on any available port (does not require capability)
  server_address.sin_port = htons(0);
#else
  server_address.sin_port = htons(443);
#endif
  // allow reuse of socket address so that restarting the server will not fail due to address in use
  static const int optval = 1;
  setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
  // assign address and listen for connections
  assert_syscall(bind, listen_socket, reinterpret_cast<sockaddr *>(&server_address), sizeof(server_address));
  assert_syscall(listen, listen_socket, 1024);
#ifdef USING_SANITIZER
  // get port number on which server is listening
  sockaddr_storage address;
  socklen_t        address_length = sizeof(address);
  assert_syscall(getsockname, listen_socket, reinterpret_cast<sockaddr *>(&address), &address_length);
  auto port = ntohs(reinterpret_cast<sockaddr_in *>(&address)->sin_port);
  logger->information("server is now listening on port {}", port);
#else
  logger->trace("server is now listening");
#endif

  logger->trace("setting up multiplexer...");
  int epoll_descriptor; // to be initialized on next line
  assert_syscall_return_value(epoll_descriptor, epoll_create1, EPOLL_CLOEXEC);
  // register rpc_fd for input events
  epoll_event event = {.events = EPOLLIN, .data = {.fd = rpc_fd}};
  assert_syscall(epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD, rpc_fd, &event);
  // register listening socket for input events
  //  note that this socket is in nonblock mode, use ET mode
  event.events  = EPOLLIN | EPOLLET;
  event.data.fd = listen_socket;
  assert_syscall(epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD, listen_socket, &event);
  logger->trace("epoll multiplexer is ready");

  std::array<epoll_event, 8> events;
  while (loop) {
    loggers->performance_logger->trace("before waiting on epoll");
    auto event_count = epoll_wait(epoll_descriptor, events.data(), events.size(), -1);
    loggers->performance_logger->trace("returned from epoll_wait");
    if (event_count == -1) {
      logger->debug("epoll_wait reported error: {}", strerror(errno));
      continue;
    }
    for (decltype(event_count) i = 0; i < event_count; i++) {
      if (events[i].data.fd == rpc_fd) {
        handle_thread_call();
        continue;
      }
      if (events[i].data.fd == listen_socket) {
        // accept connections. note that since the socket is in nonblocking mode, we must keep accepting until
        //  a potential block is reported via EAGAIN or EWOULDBLOCK
        while (true) {
          auto socket = accept(listen_socket, nullptr, nullptr); // we do not care about client address
          if (socket == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              loggers->performance_logger->trace("all connections in this batch accepted");
            } else {
              logger->error(
                "failed to accept: {}. This error is ignored for now but may cause further failure later",
                strerror(errno)
              );
            }
            break;
          }
          loggers->performance_logger->trace("start initializing a new connection");
          auto connection = std::make_unique<Connection>(socket);
          logger->trace("initializing connection " ConnectionIDFormatter, connection->identifier);
#define skip_procedure                                                                                       \
  logger->error(                                                                                             \
    "failed to call {} when initializing connection " ConnectionIDFormatter ", giving it up",                \
    api_name,                                                                                                \
    connection->identifier                                                                                   \
  );                                                                                                         \
  continue;
#define setup_check_gnutls_call(API, ...)                                                                    \
  check_gnutls_call(, skip_procedure, skip_procedure, API __VA_OPT__(, ) __VA_ARGS__)

          // initialize the session
          // note to set it GNUTLS_NONBLOCK therefore notify GnuTLS to expect nonblocking operations on it
          setup_check_gnutls_call(
            gnutls_init,
            &connection->side[Connection::SideName::Local].session,
            GNUTLS_SERVER | GNUTLS_AUTO_REAUTH | GNUTLS_NONBLOCK
          );
          // regular its security level
          setup_check_gnutls_call(
            gnutls_priority_set_direct,
            connection->side[Connection::SideName::Local].session,
            DefaultPriorityString,
            NULL
          );
          // set the certificate to use: acquired dynamically
          setup_check_gnutls_call(
            gnutls_credentials_set,
            connection->side[Connection::SideName::Local].session,
            GNUTLS_CRD_CERTIFICATE,
            x509_cred
          );
          // do not request a certificate from client side
          gnutls_certificate_server_set_request(
            connection->side[Connection::SideName::Local].session, GNUTLS_CERT_IGNORE
          );
          // setup transport layer
          gnutls_transport_set_int(
            connection->side[Connection::SideName::Local].session,
            connection->side[Connection::SideName::Local].socket_descriptor
          );

          // setup status
          connection->status = Connection::Status::LocalHandshake;
          // attach the new connection to local link list
          inbound_connections.emplace_front(std::move(connection));

          // register to epoll watcher
          event.events   = EPOLLIN | EPOLLOUT | EPOLLET;
          event.data.u64 = iterator_to_u64(inbound_connections.begin());
          check_syscall(
            ,
            skip_procedure,
            epoll_ctl,
            epoll_descriptor,
            EPOLL_CTL_ADD,
            inbound_connections.front()
              ->side[Connection::SideName::Local]
              .socket_descriptor, // connection is moved away, we cannot use it anymore
            &event
          );

          loggers->performance_logger->trace("end of connection initialization");
        }
        continue;
      }
      // when control flow reaches here, events[i] corresponds to a connection that is waiting for handshake
      auto iterator   = u64_to_iterator<decltype(inbound_connections)::iterator>(events[i].data.u64);
      auto connection = iterator->get();
      // do handshake on this session
      loggers->performance_logger->trace("before call to handshake");
      auto handshake_result = connection->handshake(*logger);
      loggers->performance_logger->trace("after call to handshake");
      if (handshake_result == ExecutionResult::Succeed) {
        // show remote hostname about connection
        logger->debug(
          "new connection " ConnectionIDFormatter " to {}", connection->identifier, connection->key->hostname
        );
        // detach instance from local list
        connection = iterator->release(); // the assignment is actually no-op which is put here just to
                                          // silent the warning about discarding return value
                                          //  what do matters is the side effect that the std::unique_ptr
                                          //  drops its ownership to the instance of connection
        inbound_connections.erase(iterator);
        // update status
        connection->status = Connection::Status::Connecting;
        // remove it from local epoll watcher
        epoll_ctl(
          epoll_descriptor,
          EPOLL_CTL_DEL,
          connection->side[Connection::SideName::Local].socket_descriptor,
          nullptr
        );
        // hand over to next stage
        //  decltype is used here just to silent the warning
        write(arguments.pipe_to_next, &connection, sizeof(decltype(connection)));
        logger->trace(
          "connection " ConnectionIDFormatter " handed over to next stage", connection->identifier
        );
      } else if (handshake_result == ExecutionResult::TryAgain) {
        // nothing to do here
      } else {
        // failed, shutdown this connection
        inbound_connections.erase(iterator);
      }
    }
  }

  // clean up
  close(epoll_descriptor);
  close(listen_socket);
  close(arguments.pipe_to_next);
  close(rpc_fd);
  inbound_connections.clear();
  gnutls_certificate_free_credentials(x509_cred);
  logger->information("exiting...");
}