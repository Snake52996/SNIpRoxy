#include "resolve.hh"
#include "cache.hh"
#include "common.hh"
#include "connection.hh"

#include <ares.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <functional>
#include <list>
#include <memory>
#include <netinet/in.h>
#include <random>
#include <ranges>
#include <string_view>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

// global logger for resolve subsystem
static LogPP::Logger *logger  = nullptr;
// shared subsystem loggers
static loggers       *loggers = nullptr;

// if the server should keep running
static bool                            loop = true;
// pipe to hand connections over to next stage
static int                             pipe_to_next;
// list of connections
std::list<std::unique_ptr<Connection>> resolve_list;

namespace {
// a wrapper abound inet_ntop that change binary IPv4/IPv6 address to human readable format
static std::string network_binary_to_text(int family, sockaddr *address) {
  char readable_address_buffer[INET6_ADDRSTRLEN];
  inet_ntop(
    family,
    family == AF_INET ? reinterpret_cast<void *>(&reinterpret_cast<sockaddr_in *>(address)->sin_addr)
                      : reinterpret_cast<void *>(&reinterpret_cast<sockaddr_in6 *>(address)->sin6_addr),
    readable_address_buffer,
    INET6_ADDRSTRLEN
  );
  return {readable_address_buffer};
}
} // namespace

struct DNSEntry {
  time_t                     valid_before; // time before which may current entry be considered as valid
  // start of entries from addrinfo
  int                        ai_family;
  int                        ai_socktype;
  int                        ai_protocol;
  socklen_t                  ai_addrlen;
  std::unique_ptr<uint8_t[]> ai_addr;
  // end of entries from addrinfo
};

class DNSCache {
  // type of keys
  using key_t           = std::string;
  // entry type associated with keys in cache
  //  use a vector since domain names may have multiple addresses
  using entry_t         = std::vector<DNSEntry>;
  // static cache that will never change or considered invalid
  //  all domain names will always be queried against this cache storage first
  using static_cache_t  = std::unordered_map<key_t, entry_t>;
  // dynamic cache will be updated dynamically when new DNS queries is performed
  //  domain names with no corresponding entry in static cache will be queried against this cache storage
  using dynamic_cache_t = Cache<key_t, entry_t, 64>;

  static_cache_t  static_cache;
  dynamic_cache_t dynamic_cache;
  std::mt19937_64 engine;

  const DNSEntry *get_random_address(entry_t *list) {
    //  note the value sampled by this distribution is in a closed range
    std::uniform_int_distribution<> arranger(0, list->size() - 1);
    return &list->at(arranger(this->engine));
  }

public:
  // initialize the cache: load static cache from file
  void load_static_cache(const std::filesystem::path &cache_file) {
    // clear static cache first
    this->static_cache.clear();

    if (cache_file.empty()) {
      return;
    }
    std::ifstream input(cache_file);
    if (!input.is_open()) {
      logger->error("failed to open cache file {}", cache_file.string());
      return;
    }
    std::string buffer;
    while (true) {
      buffer.clear();
      std::getline(input, buffer);
      if (buffer.size() == 0) {
        if (input.eof()) {
          break;
        } else {
          continue; // ignore empty lines
        }
      }

      // remove prefixed and suffixed empty characters
      size_t start = 0;
      size_t end   = buffer.size();
      while (start < buffer.size() && isspace(buffer[start])) {
        start++;
      }
      while (end != 0 && isspace(buffer[end - 1])) {
        end--;
      }
      if (start < end) {
        buffer = buffer.substr(start, end - start);
      } else {
        buffer.clear();
      }

      // ignore empty or comment lines
      if (buffer.size() == 0 || buffer[0] == '#') {
        continue;
      }

      // split the string into two parts, the first for address, second for domain name
      end = 0;
      while (end < buffer.size() && !isspace(buffer[end])) {
        end++;
      }
      auto address = buffer.substr(0, end);
      if (end == buffer.size()) {
        logger->error("invalid format on line {}: delimiter not found", buffer);
        continue;
      }
      start = end;
      while (start < buffer.size() && isspace(buffer[start])) {
        start++;
      }
      end = start;
      while (end < buffer.size() && (!isspace(buffer[end]) && buffer[end] != '#')) {
        end++;
      }
      if (end == start) {
        logger->error("invalid format on line {}: domain name not found", buffer);
        continue;
      }
      auto name = buffer.substr(start, end - start);
      logger->trace("cache file: {} -> {}", name, address);

      // build internet address from human-readable text format
      //  we use ':' as identifier of a IPv6 address
      std::unique_ptr<uint8_t[]> binary_address;
      void                      *fill_buffer;
      socklen_t                  length;
      int                        family;

      if (address.find(':') != address.npos) {
        // IPv6 address
        length            = sizeof(sockaddr_in6);
        binary_address    = std::make_unique<uint8_t[]>(length);
        auto sock_address = reinterpret_cast<sockaddr_in6 *>(binary_address.get());
        ::memset(sock_address, 0, length);
        fill_buffer               = &sock_address->sin6_addr;
        sock_address->sin6_family = AF_INET6;
        sock_address->sin6_port   = htons(443);
        family                    = AF_INET6;
      } else {
        length            = sizeof(sockaddr_in);
        binary_address    = std::make_unique<uint8_t[]>(length);
        auto sock_address = reinterpret_cast<sockaddr_in *>(binary_address.get());
        ::memset(sock_address, 0, length);
        fill_buffer              = &sock_address->sin_addr;
        sock_address->sin_family = AF_INET;
        sock_address->sin_port   = htons(443);
        family                   = AF_INET;
      }
      if (inet_pton(family, address.c_str(), fill_buffer) != 1) {
        logger->error("invalid address {}", address);
        continue;
      }

      // add this mapping to static cache
      this->static_cache.try_emplace(name);
      this->static_cache.at(name).emplace_back(
        0, family, SOCK_STREAM, IPPROTO_TCP, length, std::move(binary_address)
      );
    }
  }

  DNSCache(const std::filesystem::path &cache_file) : engine(std::random_device{}()) {
    this->load_static_cache(cache_file);
  }

  // query address of specified domain name
  //  if there are multiple addresses available, give a random one
  const DNSEntry *query(const key_t &hostname) {
    // vector from which result shall be picked randomly
    entry_t *results  = nullptr;
    // check static cache first
    auto     iterator = this->static_cache.find(hostname);
    if (iterator != this->static_cache.end()) {
      results = &iterator->second;
    } else {
      // each address may have its own valid time, we cannot check them as a whole
      //  therefore get it unconditionally and apply a filter later
      //  but we can eliminate empty lists
      results =
        this->dynamic_cache.get(hostname, [](const entry_t &entry) -> bool { return !entry.empty(); });
    }
    if (results == nullptr) {
      return nullptr; // not found
    }
    if (results->front().valid_before != 0) { // not from the static cache
      auto current_time = time(nullptr);
      // validation and filter out expired addresses
      std::erase_if(*results, [current_time](const DNSEntry &entry) -> bool {
        return entry.valid_before > current_time;
      });
    }
    if (results->empty()) {
      return nullptr; // all addresses have expired
    }
    // return a random address
    return this->get_random_address(results);
  }

  // register a hostname-to-addresses pair to (dynamic) cache
  //  the addresses shall be the result structure acquired directly from ares callback
  //  a deep copy of the returned address will be kept internally, feel free to release that result
  //  a randomly picked address will be returned
  const DNSEntry *cache(const key_t &hostname, ares_addrinfo *result) {
    // get a fixed time to avoid possible, undesired small variations
    auto    current_time = time(nullptr);
    entry_t addresses;
    for (auto entry = result->nodes; entry != nullptr; entry = entry->ai_next) {
      // deep copy ai_addr
      auto ai_addr = std::make_unique<uint8_t[]>(entry->ai_addrlen);
      memcpy(ai_addr.get(), entry->ai_addr, entry->ai_addrlen);
      // place a new entry to the list
      addresses.emplace_back(
        entry->ai_ttl + current_time, // valid_before
        entry->ai_family,             // ai_family
        entry->ai_socktype,           // ai_socktype
        entry->ai_protocol,           // ai_protocol
        entry->ai_addrlen,            // ai_addrlen
        std::move(ai_addr)            // ai_addr
      );
    }
    // insert to dynamic cache and return a random one
    return this->get_random_address(&this->dynamic_cache.set(hostname, std::move(addresses)));
  }

  // clear dynamic cache
  void clear() { this->dynamic_cache.clear(); }
};
struct callback_parameter {
  decltype(resolve_list)::iterator iterator;
  DNSCache                        &cache;
};

// create socket and initialize connect to target remote server, then hand it over to next stage
//  note that when this function returns, or more precisely, when the connection is handed over,
//  the underlying connection to remove server may (or is likely) not established yet
//  it is the responsibility of following stage to wait for completion
void proceed_connection(const DNSEntry *entry, decltype(resolve_list)::iterator iterator) {
  Connection *connection = iterator->get();

  // print the address, just for logging/debugging purpose
  auto address = network_binary_to_text(entry->ai_family, reinterpret_cast<sockaddr *>(entry->ai_addr.get()));
  logger->debug(
    "resolved for connection " ConnectionIDFormatter " : {} -> {}",
    connection->identifier,
    connection->key->hostname,
    address
  );

  // make new socket for remote connection
  connection->set_remote_socket(socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol));
  // initiate connect to remote server
  loggers->performance_logger->trace("before calling connect(2)");
  int return_value = connect(
    connection->side[Connection::SideName::Remote].socket_descriptor,
    reinterpret_cast<sockaddr *>(entry->ai_addr.get()),
    entry->ai_addrlen
  );
  loggers->performance_logger->trace("after calling connect(2)");
  if (return_value == 0 || (return_value == -1 && errno == EINPROGRESS)) {
    // release ownership
    connection = iterator->release();
    // erase node
    resolve_list.erase(iterator);
    write(pipe_to_next, &connection, sizeof(decltype(connection)));
    logger->trace("handed connection " ConnectionIDFormatter " to next stage", connection->identifier);
  } else {
    logger->error(
      "failed when connecting to {} for " ConnectionIDFormatter ": {}\n",
      address,
      connection->identifier,
      strerror(errno)
    );
    resolve_list.erase(iterator);
  }
}

void callback(void *arg, int status, [[maybe_unused]] int timeouts, ares_addrinfo *result) {
  auto        parameter  = reinterpret_cast<callback_parameter *>(arg);
  Connection *connection = parameter->iterator->get();
  if (status == ARES_SUCCESS) {
    auto entry = parameter->cache.cache(connection->key->hostname, result);
    ares_freeaddrinfo(result);
    proceed_connection(entry, parameter->iterator);
  } else {
    fprintf(stderr, "DNS failed: %s\n", ares_strerror(status));
    resolve_list.erase(parameter->iterator);
  }
  ::free(arg);
}

std::function<void()>        reload_configuration;
std::function<void()>        clear_cache;
std::function<std::string()> summary_cache;

static void summary() {
  std::string buffer =
    std::format("\n====== begin summary ======\n  {} connection(s) in this stage:\n", resolve_list.size());
  for (const auto &connection : std::ranges::reverse_view(resolve_list)) {
    buffer += std::format(
      "    connection " ConnectionIDFormatter " to {}\n", connection->identifier, connection->key->hostname
    );
  }
  buffer += summary_cache();
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
    reload_configuration();
    break;
  case ThreadCallID::ThreadCallIDClearCache:
    clear_cache();
    break;
  case ThreadCallID::ThreadCallIDSummary:
    summary();
    break;
  }
}

// entry of resolve
void resolve(resolve_parameter arguments) {
  // configure loggers
  auto logger_ = LogPP::logger.create_sub_logger("resolve");
  logger       = &logger_;

  auto performance_logger =
    arguments.common_parameters.loggers.performance_logger->create_sub_logger("resolve");
  struct loggers loggers_ {
    &performance_logger, nullptr
  };
  loggers = &loggers_;
  logger->information("starting...");

  logger->trace("masking signals...");
  mask_signals();
  logger->trace("signals masked");

  // setup global variables
  rpc_fd       = arguments.common_parameters.rpc_fd;
  pipe_to_next = arguments.pipe_to_next;

  // build caches
  logger->trace("building static cache...");
  DNSCache cache(arguments.pinned_dns_cache);
  uint32_t cache_hits{0};
  uint32_t cache_misses{0};
  logger->trace("static cache built");

  reload_configuration = [&cache, &arguments]() { cache.load_static_cache(arguments.pinned_dns_cache); };
  clear_cache          = [&cache]() { cache.clear(); };
  summary_cache        = [&cache_hits, &cache_misses]() -> std::string {
    return std::format("  {} hits, {} misses on DNS cache\n", cache_hits, cache_misses);
  };

  // setup watcher
  int epoll_descriptor; // to be initialized on next line
  assert_syscall_return_value(epoll_descriptor, epoll_create1, EPOLL_CLOEXEC);
  epoll_event event = {.events = EPOLLIN};
  event.data.fd     = arguments.pipe_from_last;
  assert_syscall(epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD, arguments.pipe_from_last, &event);
  event.data.fd = rpc_fd;
  assert_syscall(epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD, rpc_fd, &event);

  // initialize ares library
  logger->trace("initializing ares...");
  assert_ares_call(ares_library_init, ARES_LIB_INIT_ALL);
  // we assume a local DNS server
  in_addr             addr = {.s_addr = inet_addr("127.0.0.1")};
  ares_channel        channel;
  struct ares_options options = {
    .timeout       = 3000,                    // milliseconds to wait for the first try
    .tries         = 5,                       // try this many times before give up
    .servers       = &addr,                   // list of servers to use
    .nservers      = 1,                       // number of servers in the list
    .lookups       = const_cast<char *>("b"), // do DNS query, do not check local hosts file
                                              //  the cast is here to silent warnings
    .sock_state_cb = [](void *data, int socket_fd, int wait_read, int wait_write) -> void {
      auto        epoll_descriptor = static_cast<int>(reinterpret_cast<uint64_t>(data));
      epoll_event event            = {
                   .events = (wait_read * EPOLLIN) | (wait_write * EPOLLOUT), // set events conditionally
                   .data   = {.fd = socket_fd}
      };
      logger->trace(
        "descriptor {} to be watched for {}{}", socket_fd, wait_read ? 'r' : '-', wait_write ? 'w' : '-'
      );
      // try to modify configuration of event lists first, this may save a syscall
      int return_value = epoll_ctl(epoll_descriptor, EPOLL_CTL_MOD, socket_fd, &event);
      if (return_value == 0) { // succeed
        return;
      }
      if (return_value == -1 && errno == ENOENT) {
        // this file descriptor is not registered before, register it
        check_syscall(
          , logger->error("failed to add new descriptor {} for listen: {}", socket_fd, strerror(errno));
          , epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD, socket_fd, &event
        );
      } else {
        logger->error("failed to modify listened event on descriptor {}: {}", socket_fd, strerror(errno));
      }
    }, // callback to notify socket status change
    // data supplied into callback as user data
    // we simply use the epoll descriptor for now, therefore just cast it as a pointer...
    .sock_state_cb_data = reinterpret_cast<void *>(static_cast<uint64_t>(epoll_descriptor)),
  };
  assert_ares_call(
    ares_init_options,
    &channel,
    &options,
    ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_SERVERS | ARES_OPT_LOOKUPS | ARES_OPT_SOCK_STATE_CB
  );
  // hints used to query for address
  struct ares_addrinfo_hints hints = {
    .ai_flags    = ARES_AI_NOSORT, // no not try to connect to resolved addresses or sort the result
    .ai_family   = AF_UNSPEC,      // both IPv4 and IPv6 is welcomed
    .ai_socktype = SOCK_STREAM,    // use stream socket (TCP)
    .ai_protocol = 0,              // any protocol (but likely TCP)
  };
  logger->trace("ares initialized...");

  struct timeval              timeout;
  std::array<epoll_event, 16> events;
  while (loop) {
    // get timeout
    int wait_milliseconds = -1;
    if (!resolve_list.empty()) {
      // only ask ares for timeout suggestion if there are queries undergoing
      ares_timeout(channel, nullptr, &timeout);
      loggers->performance_logger->trace(
        "ares suggested timeout of {}.{:06d}", timeout.tv_sec, timeout.tv_usec
      );
      wait_milliseconds = timeout.tv_sec * 1000 + timeout.tv_usec / 1000;
      if (wait_milliseconds == 0) {
        wait_milliseconds = 1;
        loggers->performance_logger->trace("timeout too short, rounded up to 1ms");
      }
    }
    // wait for events
    loggers->performance_logger->trace("before waiting on epoll");
    auto event_count = epoll_wait(epoll_descriptor, events.data(), events.size(), wait_milliseconds);
    loggers->performance_logger->trace("returned from epoll_wait");

    // we should call ares at least once in each loop
    bool ares_called = false;
    if (event_count == -1) {
      logger->trace("epoll_wait reported error: {}", strerror(errno));
      continue;
    }
    loggers->performance_logger->trace("{} events reported by epoll", event_count);
    for (decltype(event_count) i = 0; i < event_count; i++) {
      if (events[i].data.fd == rpc_fd) {
        handle_thread_call();
        continue;
      }
      if (events[i].data.fd == arguments.pipe_from_last) {
        // receive connection from last stage
        Connection *connection;
        read(arguments.pipe_from_last, &connection, sizeof(decltype(connection)));
        // manage it into local list
        resolve_list.emplace_front(connection);
        auto cache_result = cache.query(connection->key->hostname);
        if (cache_result != nullptr) {
          // cache hit
          loggers->performance_logger->debug("cache hit for {}", connection->key->hostname);
          cache_hits++;
          proceed_connection(cache_result, resolve_list.begin());
        } else {
          loggers->performance_logger->debug("cache miss for {}", connection->key->hostname);
          cache_misses++;
          auto callback_argument =
            reinterpret_cast<callback_parameter *>(::malloc(sizeof(callback_parameter)));
          std::construct_at(callback_argument, resolve_list.begin(), cache);
          loggers->performance_logger->debug("before call to ares_getaddrinfo");
          ares_getaddrinfo(
            channel, connection->key->hostname.c_str(), "https", &hints, callback, callback_argument
          );
          loggers->performance_logger->debug("after call to ares_getaddrinfo");
        }
        continue;
      }
      // handle ares file descriptors
      ares_called = true;
      loggers->performance_logger->trace("before calling ares_process_fd");
      ares_process_fd(
        channel,
        events[i].events & EPOLLIN ? events[i].data.fd : ARES_SOCKET_BAD,
        events[i].events & EPOLLOUT ? events[i].data.fd : ARES_SOCKET_BAD
      );
      loggers->performance_logger->trace("after calling ares_process_fd");
    }
    // call once if ares is not called in this loop
    loggers->performance_logger->trace("before calling ares_process_fd");
    ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    loggers->performance_logger->trace("after calling ares_process_fd");
  }

  // clean up
  ares_destroy(channel);
  ares_library_cleanup();
  resolve_list.clear();
  close(pipe_to_next);
  close(arguments.pipe_from_last);
  close(rpc_fd);
  logger->information("exiting...");
}