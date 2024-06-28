#include "server.hh"
#include "common.hh"
#include "connection.hh"
#include "thread_common.hh"

#include <cerrno>
#include <gnutls/gnutls.h>
#include <list>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

// global logger for inbound subsystem
static LogPP::Logger *logger  = nullptr;
// shared subsystem loggers
static loggers       *loggers = nullptr;

// keep running
static bool loop = true;

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

void server(server_parameter arguments) {
  // configure loggers
  auto logger_ = LogPP::logger.create_sub_logger("server");
  logger       = &logger_;

  auto performance_logger =
    arguments.common_parameters.loggers.performance_logger->create_sub_logger("server");
  struct loggers loggers_ {
    &performance_logger, nullptr
  };
  loggers = &loggers_;
  logger->information("starting...");

  logger->trace("masking signals...");
  mask_signals();
  logger->trace("signals masked");

  rpc_fd = arguments.common_parameters.rpc_fd;
  std::list<std::unique_ptr<Connection>> server_connections;
  // we need a separate link so that connections will always keep valid till the end of the loop it is closed
  //  since multiple events (on different file descriptors of the same connection) may be reported in one loop
  //  the connection control block must keep valid or we may encounter crashes
  decltype(server_connections)           closing_connections;

  logger->trace("setting up epoll...");
  int epoll_descriptor; // to be initialized on next line
  assert_syscall_return_value(epoll_descriptor, epoll_create1, EPOLL_CLOEXEC);
  epoll_event event = {.events = EPOLLIN, .data = {.fd = arguments.pipe_from_last}};
  assert_syscall(epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD, arguments.pipe_from_last, &event);
  event.data.fd = rpc_fd;
  assert_syscall(epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD, rpc_fd, &event);
  // make events ready for register connection sockets
  event.events = EPOLLIN | EPOLLOUT | EPOLLET;
  logger->trace("epoll set up");

  static const auto shutdown_connection = [&server_connections,
                                           &closing_connections](Connection *connection) {
    closing_connections.splice(
      closing_connections.cbegin(),
      server_connections,
      u64_to_iterator<decltype(server_connections)::iterator>(connection->iterator)
    );
    connection->status = Connection::Status::ShutingDown;
  };
  // helper function to forward data
  //  return true for this connection is closed, false otherwise
  static const auto forward_data = [](Connection *connection, Side *from, Side *to) -> bool {
    loggers->performance_logger->trace("before Side::recv");
    auto result = from->recv(logger);
    loggers->performance_logger->trace("after Side::recv");
    if (result.first == ExecutionResult::Failed) {
      // fatal error encountered, shutdown the connection
      shutdown_connection(connection);
      return true;
    }
    // input collected, transmit to other side
    if (!result.second.empty()) {
      global_loggers->transport_logger->information(
        "connection " ConnectionIDFormatter ": proxy <-- {:5d} bytes --  {}",
        connection->identifier,
        result.second.size(),
        side_names[from->is_remote]
      );
      loggers->performance_logger->trace("before Side::send(data)");
      auto return_value = to->send(logger, result.second);
      loggers->performance_logger->trace("after Side::send(data)");
      if (return_value.first == ExecutionResult::Failed) {
        // fatal error encountered, shutdown the connection
        shutdown_connection(connection);
        return true;
      }
    }
    if (result.first == ExecutionResult::Succeed) {
      // EOF reached, shutdown the connection
      shutdown_connection(connection);
      return true;
    }
    return false;
  };

  std::array<epoll_event, 16> events;
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
        // accept established connection
        Connection *connection;
        read(arguments.pipe_from_last, &connection, sizeof(decltype(connection)));
        logger->debug("received connection " ConnectionIDFormatter, connection->identifier);
        // attach it into the list
        server_connections.emplace_front(connection);
        connection->iterator = iterator_to_u64(server_connections.begin());
        const auto give_up   = [connection, &server_connections]() {
          logger->error(
            "failed to register connection " ConnectionIDFormatter ", to epoll, shuting it down",
            connection->identifier
          );
          server_connections.pop_front();
        };
        event.data.ptr = &connection->side[0];
        check_syscall(, give_up();,
                                  epoll_ctl,
                                  epoll_descriptor,
                                  EPOLL_CTL_ADD,
                                  connection->side[Connection::SideName::Local].socket_descriptor,
                                  &event);
        event.data.ptr = &connection->side[1];
        check_syscall(, give_up();,
                                  epoll_ctl,
                                  epoll_descriptor,
                                  EPOLL_CTL_ADD,
                                  connection->side[Connection::SideName::Remote].socket_descriptor,
                                  &event);
        continue;
      }
      // when control flow reaches here, events[i] corresponds to a connection
      auto this_side  = reinterpret_cast<Side *>(events[i].data.ptr);
      auto connection = get_associated_connection(this_side);
      auto iterator   = u64_to_iterator<decltype(server_connections)::iterator>(connection->iterator);
      if (connection->status == Connection::Status::ShutingDown) {
        // it is on its shuting down procedure, do not touch it
        continue;
      }
      if ((events[i].events & (EPOLLIN | EPOLLOUT)) == 0) {
        // error encountered
        logger->error("connection " ConnectionIDFormatter " failed, closing...", connection->identifier);
        shutdown_connection(connection);
        continue;
      }
      // handle normal communicates
      auto that_side = get_other_side(connection, this_side);
      if (events[i].events & EPOLLOUT) {
        if (this_side->pending_write()) {
          // continue last transmit
          loggers->performance_logger->trace("before Side::send()");
          auto result = this_side->send(logger);
          loggers->performance_logger->trace("after Side::send()");
          if (result.first == ExecutionResult::Failed) {
            // fatal error encountered, shutdown the connection
            shutdown_connection(connection);
            continue;
          }
        }
        if (!this_side->pending_write() && that_side->pending_read) {
          // fetch data from other side and write to this side
          if (forward_data(connection, that_side, this_side)) {
            continue; // closed
          }
        }
      }
      if (events[i].events & EPOLLIN) {
        this_side->pending_read = true;
        if (that_side->pending_write() == false) {
          if (forward_data(connection, this_side, that_side)) {
            continue; // closed
          }
        }
        // unfortunately, GnuTLS does not always consume all bytes available in underlying socket
        //  subsequent data arrived may not be reported properly by epoll working in edge-trigger mode
        //  therefore we must reset epoll on this descriptor each time EPOLLIN is reported on it
        //  messy...
        event.data.ptr = events[i].data.ptr;
        epoll_ctl(epoll_descriptor, EPOLL_CTL_MOD, this_side->socket_descriptor, &event);
      }
    }
    closing_connections.clear();
  }

  // clean up
  close(rpc_fd);
  close(epoll_descriptor);
  close(arguments.pipe_from_last);
  logger->information("exiting...");
}