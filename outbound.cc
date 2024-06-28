#include "outbound.hh"
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

// policy specification used by local server, generally speaking we enable very secure algorithms while
// allowing some less but still quite secure ones
constexpr auto *DefaultPriorityString =
  "NONE:+VERS-TLS1.3:+COMP-ALL:+AEAD:+CTYPE-X509:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305"
  ":+GROUP-SECP256R1:+GROUP-SECP384R1:+GROUP-SECP521R1:+GROUP-X25519:+SIGN-RSA-PSS-RSAE-SHA256"
  ":+SIGN-RSA-PSS-RSAE-SHA384:+SIGN-RSA-PSS-RSAE-SHA512:+SIGN-EdDSA-Ed25519:%PROFILE_MEDIUM";
// global logger for inbound subsystem
static LogPP::Logger *logger  = nullptr;
// shared subsystem loggers
static loggers       *loggers = nullptr;

static std::list<std::unique_ptr<Connection>> outbound_connections;

// if the server should keep running
static bool loop = true;

static void summary() {
  std::string buffer = std::format(
    "\n====== begin summary ======\n  {} connection(s) in this stage:\n", outbound_connections.size()
  );
  for (const auto &connection : std::ranges::reverse_view(outbound_connections)) {
    buffer += std::format(
      "    connection " ConnectionIDFormatter " to {}\n", connection->identifier, connection->key->hostname
    );
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
    break; // nothing to reload
  case ThreadCallID::ThreadCallIDClearCache:
    break; // nothing to clear
  case ThreadCallID::ThreadCallIDSummary:
    summary();
    break;
  }
}

// entry of outbound
void outbound(outbound_parameter arguments) {
  // configure loggers
  auto logger_ = LogPP::logger.create_sub_logger("outbound");
  logger       = &logger_;

  auto performance_logger =
    arguments.common_parameters.loggers.performance_logger->create_sub_logger("outbound");
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

  logger->trace("setting up multiplexer...");
  int epoll_descriptor; // to be initialized on next line
  assert_syscall_return_value(epoll_descriptor, epoll_create1, EPOLL_CLOEXEC);
  // register rpc_fd for input events
  epoll_event event = {.events = EPOLLIN, .data = {.fd = rpc_fd}};
  assert_syscall(epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD, rpc_fd, &event);
  // register input pipe from last stage for input events
  event.data.fd = arguments.pipe_from_last;
  assert_syscall(epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD, arguments.pipe_from_last, &event);
  logger->trace("epoll multiplexer is ready");

  // prepare default trust certificates
  logger->trace("loading system trust...");
  gnutls_certificate_credentials_t xcred;
  assert_gnutls_call(gnutls_certificate_allocate_credentials, &xcred);
  assert_gnutls_call(gnutls_certificate_set_x509_system_trust, xcred);
  logger->trace("system trust loaded");

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
      if (events[i].data.fd == arguments.pipe_from_last) {
        // accept connection
        Connection *connection;
        read(arguments.pipe_from_last, &connection, sizeof(decltype(connection)));
        logger->trace("received connection " ConnectionIDFormatter, connection->identifier);
        // attach it into the list
        outbound_connections.emplace_front(connection);
#define skip_procedure                                                                                       \
  logger->error(                                                                                             \
    "failed to call {} when initializing connection " ConnectionIDFormatter ", giving it up",                \
    api_name,                                                                                                \
    connection->identifier                                                                                   \
  );                                                                                                         \
  outbound_connections.pop_front();                                                                          \
  continue;
#define setup_check_gnutls_call(API, ...)                                                                    \
  check_gnutls_call(, skip_procedure, skip_procedure, API __VA_OPT__(, ) __VA_ARGS__)

        // initialize remote session
        // note to set it GNUTLS_NONBLOCK therefore notify GnuTLS to expect nonblocking operations on it
        setup_check_gnutls_call(
          gnutls_init,
          &connection->side[Connection::SideName::Remote].session,
          GNUTLS_CLIENT | GNUTLS_NO_AUTO_SEND_TICKET | GNUTLS_NONBLOCK
        );
        // regular its security level
        setup_check_gnutls_call(
          gnutls_priority_set_direct,
          connection->side[Connection::SideName::Remote].session,
          DefaultPriorityString,
          NULL
        );
        // set the certificates to trust
        setup_check_gnutls_call(
          gnutls_credentials_set,
          connection->side[Connection::SideName::Remote].session,
          GNUTLS_CRD_CERTIFICATE,
          xcred
        );
        // set domain name to check server's certificate against
        gnutls_session_set_verify_cert(
          connection->side[Connection::SideName::Remote].session, connection->key->hostname.c_str(), 0
        );
        // setup transport layer
        gnutls_transport_set_int(
          connection->side[Connection::SideName::Remote].session,
          connection->side[Connection::SideName::Remote].socket_descriptor
        );

        // register to epoll watcher
        event.events   = EPOLLOUT | EPOLLET; // watch for writable only since we are waiting for completion of
                                             // connection to remote server
        event.data.u64 = iterator_to_u64(outbound_connections.begin());
        check_syscall(
          ,
          skip_procedure,
          epoll_ctl,
          epoll_descriptor,
          EPOLL_CTL_ADD,
          connection->side[Connection::SideName::Remote].socket_descriptor,
          &event
        );
        // note that since this socket can be still connecting to remote server, we cannot do handshake here
        //  instead, do it when EPOLLOUT is reported
        continue;
      }
      // when control flow reaches here, events[i] corresponds to a connection
      auto iterator   = u64_to_iterator<decltype(outbound_connections)::iterator>(events[i].data.u64);
      auto connection = iterator->get();
      if ((events[i].events & (EPOLLIN | EPOLLOUT)) == 0) {
        // error encountered, give this connection up
        logger->error("connection " ConnectionIDFormatter " failed, closing...", connection->identifier);
        outbound_connections.erase(iterator);
        continue;
      }
      // either readable or writable
      if (connection->status == Connection::Status::Connecting) {
        // connected
        logger->trace("connection " ConnectionIDFormatter " reached remote server", connection->identifier);
        // update state
        connection->status = Connection::Status::RemoteHandshake;
        // re-register it with epoll to watch both readable and writable status
        epoll_event event  = {.events = EPOLLIN | EPOLLOUT | EPOLLET, .data = {.u64 = events[i].data.u64}};
        epoll_ctl(
          epoll_descriptor,
          EPOLL_CTL_MOD,
          connection->side[Connection::SideName::Remote].socket_descriptor,
          &event
        );
        // no need to continue now: we shall perform handshake anyway
      }
      // do handshake on this session
      loggers->performance_logger->trace("before call to handshake");
      auto handshake_result = connection->handshake(*logger);
      loggers->performance_logger->trace("after call to handshake");
      if (handshake_result == ExecutionResult::Succeed) {
        logger->debug("connection " ConnectionIDFormatter " established", connection->identifier);
        // detach instance from local list
        connection = iterator->release();
        outbound_connections.erase(iterator);
        // update status
        connection->status = Connection::Status::Established;
        // remove it from local epoll watcher
        epoll_ctl(
          epoll_descriptor,
          EPOLL_CTL_DEL,
          connection->side[Connection::SideName::Remote].socket_descriptor,
          nullptr
        );
        // hand over to next stage
        write(arguments.pipe_to_next, &connection, sizeof(decltype(connection)));
        logger->trace(
          "connection " ConnectionIDFormatter " handed over to next stage", connection->identifier
        );
      } else if (handshake_result == ExecutionResult::TryAgain) {
        // nothing to do here
      } else {
        // failed, shutdown this connection
        outbound_connections.erase(iterator);
      }
    }
  }

  // clean up
  close(epoll_descriptor);
  gnutls_certificate_free_credentials(xcred);
  close(arguments.pipe_to_next);
  close(arguments.pipe_from_last);
  close(rpc_fd);
  outbound_connections.clear();
  logger->information("exiting...");
}