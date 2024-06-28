#ifndef SNIPROXY_CONNECTION_HH_
#define SNIPROXY_CONNECTION_HH_
#include "key_management.hh"

#include <logpp.hh>

#include <cstdint>
#include <gnutls/gnutls.h>
#include <memory>
#include <string>
#include <tuple>

#if 0 // will be very happy to have a custom formatter to simplify the output
#include <format>
struct connection_id {
  using value_type = uint32_t;
  value_type value;
};
template <> struct std::formatter<connection_id, char> {
  template <typename ParseContext> constexpr typename ParseContext::iterator parse(ParseContext &context) {
    // allows no format arguments, provides only a dummy parser
    if (context.begin() != context.end() && *context.begin() != '}') {
      throw std::format_error("Invalid format arguments for connection_id.");
    }
    return context.end();
  }

  template <typename FmtContext>
  typename FmtContext::iterator format(connection_id &id, FmtContext &context) const {
    // simply use formatter for underlying type with fixed style
    return std::ranges::copy(std::format("{:06d}", id.value), context.out()).out;
  }
};
#endif

#define ConnectionIDFormatter "{:06d}"

enum class ExecutionResult { Succeed, Failed, TryAgain };

// names of the sides
constexpr auto side_names = std::to_array<const char *>({"local client", "remote server"});

// make file descriptor nonblock
void set_nonblock(int file_descriptor);

// helper to work with epoll
struct Side {
  int              socket_descriptor{-1};
  bool             pending_read{false}; // there is data ready for read from this side
  bool             is_remote;           // if this is the remote side
  gnutls_session_t session{nullptr};
  std::string      pending_data; // data to be written to this side
  ~Side();

  // unified checker for is there are data to be written
  inline bool pending_write() const { return !this->pending_data.empty(); }
  // receive data from this side
  //  return execution result, last return value from GnuTLS and the data read
  std::tuple<ExecutionResult, ssize_t, std::string> recv(LogPP::Logger *logger);
  // send pending data to this side
  //  return execution result and total bytes transferred
  std::pair<ExecutionResult, ssize_t>               send(LogPP::Logger *logger);
  // send fresh data to this side
  //  return execution result and total bytes transferred
  std::pair<ExecutionResult, ssize_t>               send(LogPP::Logger *logger, const std::string &data);
};

// control block for connection(s)
struct Connection {

  enum SideName : size_t {
    Local  = 0, // local side
    Remote = 1, // remote side
  };
  enum class Status {
    Inbound,         // connection received from local side
    LocalHandshake,  // doing handshake with local client
    Connecting,      // dialing remote server
    RemoteHandshake, // doing handshake with remote server
    Established,     // connection to both side is up and ready for data transmission
    ShutingDown,     // shuting down both side of this connection
  } status;
  uint32_t identifier; // a simple, increasing counter serves as a unique identifier for every connection
  std::shared_ptr<KeyPair> key; // key and certificate to communicate with local client

  std::array<Side, 2> side; // sides of this connection

  uint64_t iterator;     // iterator to the list holds this connection, only available in server stage
  time_t   link_time{0}; // timestamp when this connection is attached onto this link

  // these counters count only real data transmitted, handshake/retransmission etc. not taken into account
  uint32_t download_bytes{0}; // bytes downloaded, i.e. transmitted from remote server to local client
  uint32_t upload_bytes{0};   // bytes uploaded, i.e. transmitted from local client to remote server

  Connection(int socket_fd);
  Connection(const Connection &)            = delete;
  Connection(Connection &&)                 = delete;
  Connection &operator=(const Connection &) = delete;
  Connection &operator=(Connection &&)      = delete;

  void            set_remote_socket(int socket_descriptor);
  void            set_iterator(uint64_t iterator);
  // do handshake in non-blocking mode according to current state
  ExecutionResult handshake(LogPP::Logger &logger);
};

// get pointer to Connection from pointer to Side
inline Connection *get_associated_connection(Side *side) {
  return reinterpret_cast<Connection *>(
    reinterpret_cast<uint8_t *>(side) - (offsetof(Connection, side) + side->is_remote * sizeof(Side))
  );
}
// get other side in the same connection
inline Side *get_other_side(Connection *connection, Side *side) {
  return &connection->side[1 - side->is_remote];
}

#endif