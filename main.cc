#include "common.hh"
#include "inbound.hh"
#include "outbound.hh"
#include "resolve.hh"
#include "server.hh"
#include "thread_common.hh"

#include <configuration.hh>
#include <logpp.hh>

#include <csignal>
#include <filesystem>
#include <print>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <vector>

class Parser : public Configurations {
public:
  Parser() {
    this->add_option(
      "--ca-key",
      Configurations::DynamicOptionConfig()
        .parser(Configurations::CommonParsers::identity_parser)
        .argument_count(1)
    );
    this->add_option(
      "--cache",
      Configurations::DynamicOptionConfig()
        .parser(Configurations::CommonParsers::identity_parser)
        .argument_count(1)
    );
    this->add_option(
      "--verbose",
      Configurations::DynamicOptionConfig()
        .parser([](pai_t begin, pai_t end) {
          if (begin == end) {
            return std::make_any<uint8_t>(LogPP::LogLevel::debug);
          }
          return std::make_any<uint8_t>(CommonParsers::full_convert_unsigned<uint8_t>(*begin));
        })
        .argument_count(1)
        .optional_argument(true)
    );
    this->add_option(
      "--debug",
      Configurations::DynamicOptionConfig()
        .parser([](pai_t begin, pai_t end) {
          return std::unordered_set<std::string_view>{begin, end};
        })
        .argument_count(OptionConfig::VariableArguments)
    );
  }
  void help() const override {
    using std::println;
    println("snir v{}", VERSION);
    println("Simple proxy that keep SNI from leaking information about the domain visited   ");
    println("                                                                               ");
    println("Usage: snir [OPTIONS...]                                                       ");
    println("OPTIONS                                                                        ");
    println("  --ca-key  PATH      specify the path to directory under which certificate and");
    println("                       key of the CA will be stored/is stored. If not specified");
    println(
      "                       defaults to current working directory [{}]",
      std::filesystem::current_path().string()
    );
    println("                                                                               ");
    println("  --cache  FILE       specify a file whose format shall follow file  /etc/hosts");
    println("                       entries in which will be added as DNS caches in start up");
    println("                       sequence that will never expire                         ");
    println("                                                                               ");
    println("  --verbose [LEVEL]   specify the logging level which defaults to information. ");
    println("                       If no argument is given, add one level to verbosity that");
    println("                       results in debug, or taking an integer as argument  that");
    println(
      "                       specifies verbosity: 0 will turn all loggings on while {}",
      static_cast<uint8_t>(LogPP::LogLevel::Silent)
    );
    println("                       will silent the logging system entirely                 ");
    println("                                                                               ");
    println("  --debug SYSTEM...   set extra subsystem(category) to debug, which will enable");
    println("                       extra logging for them. Note that their output are still");
    println("                       controlled by logging level,  therefore you may want  to");
    println("                       combine this with --verbose 0                           ");
    println("                      subsystems available:                                    ");
    println("                       performance: for blocking time analysis                 ");
    println("                       transport: for data transfer analysis                   ");
  }
};
struct Option {
  std::filesystem::path                key_path{std::filesystem::current_path()};
  std::filesystem::path                cache_file{};
  LogPP::LogLevel                      log_level{LogPP::LogLevel::information};
  std::unordered_set<std::string_view> debugging_subsystems{};
  Option(Configurations::parse_result_t result) {
    if (result.contains("ca-key")) {
      this->key_path = std::any_cast<std::string>(result.at("ca-key"));
    }
    if (result.contains("cache")) {
      this->cache_file = std::any_cast<std::string>(result.at("cache"));
    }
    if (result.contains("verbose")) {
      auto temporary  = std::any_cast<std::uint8_t>(result.at("verbose"));
      temporary       = std::max(temporary, static_cast<uint8_t>(1));
      temporary       = std::min(temporary, static_cast<uint8_t>(LogPP::LogLevel::Silent - 1));
      this->log_level = static_cast<LogPP::LogLevel>(temporary);
    }
    if (result.contains("debug")) {
      this->debugging_subsystems = std::any_cast<std::unordered_set<std::string_view>>(result.at("debug"));
    }
  }
};

struct thread_control_block {
  std::thread thread;
  int         rcp_descriptor;

  template <typename... Args>
  thread_control_block(int rcp_descriptor, Args &&...args)
    : thread(std::forward<Args>(args)...), rcp_descriptor(rcp_descriptor) {}
};
std::vector<thread_control_block> threads;

loggers *global_loggers;

void signal_handler(int signal) {
  ThreadCallID call_id;
  if (signal == SIGINT || signal == SIGQUIT || signal == SIGTERM) {
    call_id = ThreadCallID::ThreadCallIDExit;
  } else if (signal == SIGHUP) {
    call_id = ThreadCallID::ThreadCallIDReload;
  } else if (signal == SIGIO) {
    call_id = ThreadCallID::ThreadCallIDSummary;
  } else if (signal == SIGUSR1) {
    call_id = ThreadCallID::ThreadCallIDClearCache;
  }
  for (auto &thread : threads) {
    write(thread.rcp_descriptor, &call_id, sizeof(call_id));
  }
}

int main(int argc, char **argv) {
  Option option(Parser().parse(argc, argv));
  LogPP::logger.set_log_level(option.log_level);
  LogPP::logger.information("launching SNIProxy v" VERSION "...");
  // prepare loggers
  auto performance_logger = LogPP::logger.create_sub_logger("performance");
  performance_logger.set_log_level(
    option.debugging_subsystems.contains("performance") ? LogPP::LogLevel::Full : LogPP::LogLevel::Silent
  );
  auto transport_logger = LogPP::logger.create_sub_logger("transport");
  transport_logger.set_log_level(
    option.debugging_subsystems.contains("transport") ? LogPP::LogLevel::Full : LogPP::LogLevel::Silent
  );
  loggers loggers{&performance_logger, &transport_logger};
  global_loggers = &loggers;
  assert_gnutls_call(gnutls_global_init);

  int inbound_to_resolve_pipes[2];
  { // launch stage 1: inbound, which accepts connections from local clients
    int rpc_pipes[2];
    pipe(rpc_pipes);
    pipe(inbound_to_resolve_pipes);
    inbound_parameter parameter{{rpc_pipes[0], loggers}, inbound_to_resolve_pipes[1], option.key_path};
    threads.emplace_back(rpc_pipes[1], inbound, parameter);
  }

  int resolve_to_outbound_pipes[2];
  { // launch stage 2: resolve, which queries DNS server to resolve hostname acquired from SNI information
    int rpc_pipes[2];
    pipe(rpc_pipes);
    pipe(resolve_to_outbound_pipes);
    resolve_parameter parameter{
      {rpc_pipes[0], loggers}, inbound_to_resolve_pipes[0], resolve_to_outbound_pipes[1], option.cache_file
    };
    threads.emplace_back(rpc_pipes[1], resolve, parameter);
  }

  int outbound_to_server_pipes[2];
  { // launch stage 3: outbound, which connect to remove server and perform handshake with which
    int rpc_pipes[2];
    pipe(rpc_pipes);
    pipe(outbound_to_server_pipes);
    outbound_parameter parameter{
      {rpc_pipes[0], loggers}, resolve_to_outbound_pipes[0], outbound_to_server_pipes[1]
    };
    threads.emplace_back(rpc_pipes[1], outbound, parameter);
  }

  { // launch stage 4: sever, the actual man-in-the-middle copy proxy
    int rpc_pipes[2];
    pipe(rpc_pipes);
    server_parameter parameter{{rpc_pipes[0], loggers}, outbound_to_server_pipes[0]};
    threads.emplace_back(rpc_pipes[1], server, parameter);
  }

  // handle signals
  signal(SIGINT, signal_handler);
  signal(SIGQUIT, signal_handler);
  signal(SIGTERM, signal_handler);
  signal(SIGHUP, signal_handler);
  signal(SIGIO, signal_handler);
  signal(SIGUSR1, signal_handler);
  for (auto &thread : threads) {
    thread.thread.join();
  }

  gnutls_global_deinit();
  LogPP::logger.information("exiting SNIProxy v" VERSION "...");

  return 0;
}