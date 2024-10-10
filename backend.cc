#include "backend.hh"
#include "common.hh"
#include "thread_common.hh"
#include "webpage.hh"

#include <arpa/inet.h>
#include <cmath>
#include <ctime>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <set>
#include <string_view>
#include <sys/epoll.h>
#include <unistd.h>

std::atomic_uint64_t bytes_uploaded{0};
std::atomic_uint64_t bytes_downloaded{0};

constexpr int              MeasureInterval = 500;
constexpr std::string_view NonceHeaderName{"Sec-WebSocket-Key"};
constexpr std::string_view WebpageHeader{
  "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-type: text/html\r\n\r\n"
};
constexpr std::string_view WebSocketMagic{"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"};
constexpr std::string_view WebSocketHeader{
  "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
};
constexpr size_t SHA1DigestSize    = 20;
constexpr size_t EncodedDigestSize = (SHA1DigestSize + 2) / 3 * 4;

// entry of backend
void backend(backend_parameter arguments) {
  // configure loggers
  auto logger = LogPP::logger.create_sub_logger("backend");
  // save rpc file descriptor
  auto rpc_fd = arguments.common_parameters.rpc_fd;

  logger.trace("masking signals...");
  mask_signals();
  logger.trace("signals masked");
  logger.trace("setting up listening port...");
  // create a socket
  int listen_socket; // to be initialized on next line
  assert_syscall_return_value(listen_socket, socket, AF_INET, SOCK_STREAM, 0);
  // hardcode server address as 127.0.0.1(localhost) and port as 15477
  sockaddr_in server_address;
  memset(&server_address, '\0', sizeof(server_address));
  server_address.sin_family      = AF_INET;
  server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
  server_address.sin_port        = htons(15477);
  // allow reuse of socket address so that restarting the server will not fail due to address in use
  static const int optval        = 1;
  setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
  // assign address and listen for connections
  assert_syscall(bind, listen_socket, reinterpret_cast<sockaddr *>(&server_address), sizeof(server_address));
  assert_syscall(listen, listen_socket, 5);
  logger.trace("backend is now listening");

  logger.trace("setting up multiplexer...");
  int epoll_descriptor; // to be initialized on next line
  assert_syscall_return_value(epoll_descriptor, epoll_create1, EPOLL_CLOEXEC);
  // register rpc_fd for input events
  epoll_event event = {.events = EPOLLIN, .data = {.fd = rpc_fd}};
  assert_syscall(epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD, rpc_fd, &event);
  // register listening socket for input events
  //  note that this socket is in nonblock mode, use ET mode
  event.events  = EPOLLIN;
  event.data.fd = listen_socket;
  assert_syscall(epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD, listen_socket, &event);
  logger.trace("epoll multiplexer is ready");

  std::array<epoll_event, 8> events;
  std::set<int>              clients;

  int timeout = 0;

  bool loop = true;
  while (loop) {
    if (timeout == 0) {
      timeout = MeasureInterval;
      // send current rate to all clients
      // construct data frame first
      auto download_rate =
        static_cast<uint64_t>(round(static_cast<long double>(bytes_downloaded) / MeasureInterval * 1000));
      bytes_downloaded = 0;
      auto upload_rate =
        static_cast<uint64_t>(round(static_cast<long double>(bytes_uploaded) / MeasureInterval * 1000));
      bytes_uploaded = 0;
      if (!clients.empty()) {
        auto payload = std::format(R"({{"download": "{}", "upload": "{}"}})", download_rate, upload_rate);
        logger.trace("serving: {}", payload);
        std::array<uint8_t, 2> header;
        header[0] = 0b10000001; // finished text message
        header[1] = static_cast<uint8_t>(payload.size());
        for (const auto client : clients) {
          send(client, header.data(), header.size(), MSG_NOSIGNAL | MSG_MORE);
          send(client, payload.data(), payload.size(), MSG_NOSIGNAL);
          logger.trace("sent to client at descriptor {}", client);
        }
      }
    }
    timespec start_time; // record for how long we have been blocked by epoll_wait
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    auto event_count = epoll_wait(epoll_descriptor, events.data(), events.size(), timeout);
    if (event_count == -1) {
      logger.debug("epoll_wait reported error: {}", strerror(errno));
      continue;
    }
    timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    // update timeout
    int milliseconds_passed = static_cast<int>(end_time.tv_sec - start_time.tv_sec) * 1000;
    if (end_time.tv_nsec < start_time.tv_nsec) {
      end_time.tv_nsec += 1000000000;
      milliseconds_passed -= 1000;
    }
    milliseconds_passed += static_cast<int>(end_time.tv_nsec - start_time.tv_nsec) / 1000000;
    timeout = timeout > milliseconds_passed ? timeout - milliseconds_passed : 0;

    for (decltype(event_count) i = 0; i < event_count; i++) {
      // handle thread call
      if (events[i].data.fd == rpc_fd) {
        ThreadCallID call_id;
        read(rpc_fd, &call_id, sizeof(call_id));
        switch (call_id) {
        case ThreadCallID::ThreadCallIDExit:
          loop = false;
          break;
        default:
          break;
        }
        continue;
      }

      // accept new connection
      if (events[i].data.fd == listen_socket) {
        auto client = accept(listen_socket, nullptr, nullptr);
        if (client == -1) {
          logger.error(
            "failed to accept: {}. This error is ignored for now but may cause further failure later",
            strerror(errno)
          );
        }
        // we except receiving message immediately from any client connected
        std::array<char, 512> buffer;
        std::string           request;
        while (true) {
          auto read_count = recv(client, buffer.data(), buffer.size(), 0);
          if (read_count <= 0) {
            if (read_count == -1) {
              logger.debug("error on reading from new connection: {}", strerror(errno));
            } else {
              logger.debug("connection is closed by client");
            }
            close(client);
            client = -1;
            break;
          }
          request.append(buffer.data(), read_count);
          if (request.ends_with("\r\n\r\n")) {
            break;
          }
        }

        if (client == -1) {
          continue;
        }
        auto nonce_header = request.find(NonceHeaderName);
        if (nonce_header == request.npos) {
          // plain GET request, reply with the webpage
          send(client, WebpageHeader.data(), WebpageHeader.size(), MSG_NOSIGNAL | MSG_MORE);
          send(client, webpage, webpage_len, MSG_NOSIGNAL);
          close(client);
          continue;
        }
        // this request is establishing a WebSocket connection, get the nonce first
        nonce_header += NonceHeaderName.size() + 1; // points the character after ':'
        while (isspace(request[nonce_header])) {
          nonce_header++;
        }
        auto nonce_end = request.find("\r\n", nonce_header);
        auto nonce     = request.substr(nonce_header, nonce_end - nonce_header);
        // calculate Sec-WebSocket-Accept
        nonce.append(WebSocketMagic);
        std::array<uint8_t, SHA1DigestSize> digest;
        gnutls_hash_fast(GNUTLS_DIG_SHA1, nonce.c_str(), nonce.size(), digest.data());
        gnutls_datum_t source  = {.data = digest.data(), .size = digest.size()};
        gnutls_datum_t encoded = {.data = nullptr, .size = 0};
        gnutls_base64_encode2(&source, &encoded);
        // reply to client
        send(client, WebSocketHeader.data(), WebSocketHeader.size(), MSG_NOSIGNAL | MSG_MORE);
        send(client, encoded.data, encoded.size, MSG_NOSIGNAL | MSG_MORE);
        send(client, "\r\n\r\n", 4, MSG_NOSIGNAL);
        gnutls_free(encoded.data);

        logger.trace("new client with file descriptor {} has joined", client);

        // register this client
        event.data.fd = client;
        event.events  = EPOLLRDHUP | EPOLLERR | EPOLLHUP;
        epoll_ctl(epoll_descriptor, EPOLL_CTL_ADD, client, &event);
        clients.emplace(client);
        continue;
      }

      // handle closed client connection
      auto client = events[i].data.fd;
      logger.trace("client with file descriptor {} has left", client);
      clients.erase(client);
      close(client);
    }
  }
}