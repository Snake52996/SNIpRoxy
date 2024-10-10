#include "connection.hh"
#include "backend.hh"
#include "common.hh"

#include <atomic>
#include <ctime>
#include <fcntl.h>
#include <string_view>
#include <unistd.h>
#include <utility>

namespace {
// helper for data transfer on GnuTLS sessions
//  this function loops on the specified call with arguments passed until
//   - the call succeed, indicated by non-negative return value
//   - the call failed with GNUTLS_E_AGAIN, which suggests this operation would otherwise block
//   - the call failed with fatal error, checked by gnutls_error_is_fatal
//  all other errors are reported but ignored
template <typename... Args>
auto transfer_helper(
  // begin of logging utilities
  LogPP::Logger                      *logger,
  Connection                         &connection,
  Side                               &side,
  std::string_view                    function_name, // what is the function called
  std::string_view                    explanation,   // what are we doing here
  // begin of function specifications
  const std::invocable<Args...> auto &function,
  Args &&...args
) -> std::pair<ExecutionResult, std::invoke_result_t<decltype(function), Args...>> {
  std::invoke_result_t<decltype(function), Args...> return_value;
  while (true) {
    // do the function all
    return_value = function(std::forward<Args>(args)...);
    logger->trace(
      "{} returned {}({}) on connection " ConnectionIDFormatter,
      function_name,
      return_value,
      gnutls_strerror(return_value),
      connection.identifier
    );
    // we loop until either
    if (
      return_value >= 0                      // the call succeed, or
      || return_value == GNUTLS_E_AGAIN      // the procedure shall block, or
      || gnutls_error_is_fatal(return_value) // a fatal error is received
    ) {
      break;
    }
    if (return_value == GNUTLS_E_WARNING_ALERT_RECEIVED) {
      // show the alert as warning and ignore it
      logger->warning(
        "TLS warning alert received from connection " ConnectionIDFormatter " when {}: {}",
        connection.identifier,
        explanation,
        gnutls_alert_get_name(gnutls_alert_get(side.session))
      );
    }
  }
  if (return_value >= 0) {
    logger->trace("{} succeed on connection " ConnectionIDFormatter, explanation, connection.identifier);
    return {ExecutionResult::Succeed, return_value};
  } else if (return_value == GNUTLS_E_AGAIN) {
    logger->trace(
      "{} on connection " ConnectionIDFormatter " would block, continue on later",
      explanation,
      connection.identifier
    );
    return {ExecutionResult::TryAgain, return_value};
  } else {
    // fatal error encountered
    if (return_value == GNUTLS_E_FATAL_ALERT_RECEIVED) {
      logger->error(
        "TLS fatal alert received on connection " ConnectionIDFormatter " when {}: {}",
        connection.identifier,
        explanation,
        gnutls_alert_get_name(gnutls_alert_get(side.session))
      );
    } else {
      logger->error(
        "fatal error when {} on connection " ConnectionIDFormatter ": {}",
        explanation,
        connection.identifier,
        gnutls_strerror(return_value)
      );
    }
    return {ExecutionResult::Failed, return_value};
  }
}
} // namespace

Side::~Side() {
  // session context pointer is initialized with nullptr, so it is always safe to call gnutls_deinit on them
  gnutls_deinit(this->session);
  // descriptor is either received from accept(2) or initialized by -1, it is also safe to close them
  close(this->socket_descriptor);
}

std::tuple<ExecutionResult, ssize_t, std::string> Side::recv(LogPP::Logger *logger) {
  auto connection = get_associated_connection(this);
  auto explanation =
    this->is_remote ? "reading fresh data from remote server" : "reading fresh data from local client";
  // fail the call if this side does not have pending_read bit set
  if (!this->pending_read) {
    logger->error(
      "try {} on connection " ConnectionIDFormatter " when pending_read bit is not set",
      explanation,
      connection->identifier
    );
    return {ExecutionResult::Failed, -EINVAL, {}};
  }
  constexpr size_t                 StepBufferSize = 0x4000;
  std::array<char, StepBufferSize> step_buffer;
  std::string                      full_buffer;
  while (true) {
    auto result = transfer_helper(
      logger,
      *connection,
      *this,
      "gnutls_record_recv",
      explanation,
      gnutls_record_recv,
      this->session,
      step_buffer.data(),
      step_buffer.size()
    );
    if (result.first == ExecutionResult::Failed) {
      return {result.first, result.second, std::move(full_buffer)};
    }
    if (result.first != ExecutionResult::Succeed || result.second == 0) {
      // any data available must have been consumed when we reached here, set pending status
      this->pending_read = false;
      return {result.first, result.second, std::move(full_buffer)};
    }
    full_buffer.append(step_buffer.data(), result.second);
  }
}

std::pair<ExecutionResult, ssize_t> Side::send(LogPP::Logger *logger) {
  auto connection  = get_associated_connection(this);
  auto explanation = std::string("resuming interrupted transmission to ") + side_names[this->is_remote];
  // fail the call if this side does not have pending_write bit set
  if (!this->pending_write()) {
    logger->error(
      "try {} on connection " ConnectionIDFormatter " when no data to be written",
      explanation,
      connection->identifier
    );
    return {ExecutionResult::Failed, -EINVAL};
  }
  // move this->pending_data out so that this side acts as if no data pending on it
  auto data = std::move(this->pending_data);
  return this->send(logger, data);
}

std::pair<ExecutionResult, ssize_t> Side::send(LogPP::Logger *logger, const std::string &data) {
  auto connection  = get_associated_connection(this);
  auto explanation = std::string("sending data to ") + side_names[this->is_remote];
  // fail the call if this side have pending_write bit set
  if (this->pending_write()) {
    logger->error(
      "try {} on connection " ConnectionIDFormatter " when there are data pending",
      explanation,
      connection->identifier
    );
    return {ExecutionResult::Failed, -EINVAL};
  }

  ssize_t data_transferred = 0;
  while (data_transferred < data.size()) {
    auto result = transfer_helper(
      logger,
      *connection,
      *this,
      "gnutls_record_send",
      explanation,
      gnutls_record_send,
      this->session,
      data.data() + data_transferred, // align start offset
      data.size() - data_transferred  // and buffer size
    );
    if (result.first == ExecutionResult::TryAgain) {
      // no data written in this round, save remaining data for subsequent transmission
      this->pending_data = data.substr(data_transferred);
      // keep return value consist
      result.second      = data_transferred;
    }
    if (result.first != ExecutionResult::Succeed) {
      // failed or blocked, break and report result
      return result;
    }
    // result.first == ExecutionResult::Succeed, some data is transmitted successfully
    // update total data transferred
    data_transferred += result.second;
    // show log about transmit
    global_loggers->transport_logger->information(
      "connection " ConnectionIDFormatter ": proxy  -- {:5d} bytes --> {}",
      connection->identifier,
      result.second,
      side_names[this->is_remote]
    );
    // record bytes we uploaded/downloaded
    if (this->is_remote) {
      // if we are sending to remote server, we are uploading
      bytes_uploaded += result.second;
    } else {
      // if we are sending to local client, we are downloading
      bytes_downloaded += result.second;
    }
  }
  // successfully transmitted all data supplied
  return {ExecutionResult::Succeed, data.size()};
}

void set_nonblock(int file_descriptor) {
  auto flags = fcntl(file_descriptor, F_GETFL);
  flags |= O_NONBLOCK;
  fcntl(file_descriptor, F_SETFL, flags);
}

Connection::Connection(int socket_fd) : status(Status::Inbound), key(nullptr) {
  static std::atomic<decltype(Connection::identifier)> counter = 0;
  this->identifier                              = counter.fetch_add(1, std::memory_order::relaxed);
  this->side[SideName::Local].socket_descriptor = socket_fd;
  set_nonblock(this->side[SideName::Local].socket_descriptor);
  this->side[SideName::Local].is_remote  = false;
  this->side[SideName::Remote].is_remote = true;
}

void Connection::set_remote_socket(int socket_descriptor) {
  this->side[SideName::Remote].socket_descriptor = socket_descriptor;
  set_nonblock(this->side[SideName::Remote].socket_descriptor);
}
void Connection::set_iterator(uint64_t iterator) {
  this->link_time = time(nullptr);
  this->iterator  = iterator;
}

ExecutionResult Connection::handshake(LogPP::Logger &logger) {
  std::string_view explanation;
  Side            *side;
  if (this->status == Status::LocalHandshake) {
    side        = &this->side[SideName::Local];
    explanation = "handshake with local client";
  } else {
    side        = &this->side[SideName::Remote];
    explanation = "handshake with remote server";
  }
  return transfer_helper(
           &logger, *this, *side, "gnutls_handshake", explanation, gnutls_handshake, side->session
  )
    .first;
}