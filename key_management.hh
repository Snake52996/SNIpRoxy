#ifndef SNIPROXY_KEY_MANAGEMENT_HH_
#define SNIPROXY_KEY_MANAGEMENT_HH_
#include "cache.hh"

#include <filesystem>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <memory>
#include <string_view>
struct KeyPair {
  std::string      hostname; // hostname of which this key pair is for
  gnutls_pcert_st  cert;
  gnutls_privkey_t key;

  ~KeyPair();
};
class KeyManager {
public:
  KeyManager(const KeyManager &)            = delete;
  KeyManager(KeyManager &&)                 = delete;
  KeyManager &operator=(const KeyManager &) = delete;
  KeyManager &operator=(KeyManager &&)      = delete;
  ~KeyManager();

  // require an instance of key manager
  //  requests will return the same instance if and only if to which the same path is specified
  static KeyManager &get_manager(const std::filesystem::path &key_path);

  // get a key pair that can be used to establish TLS connection with local client as host of hostname
  std::shared_ptr<KeyPair> get_key_pair(std::string_view hostname);

  // redo CA keys loading procedure
  void reload();
  // clear internal cache
  void clear();

private:
  static constexpr size_t MaxKeypair = 128;

  const std::filesystem::path                             &key_path;
  gnutls_x509_crt_t                                        ca_cert{nullptr};
  gnutls_x509_privkey_t                                    ca_key{nullptr};
  Cache<std::string, std::shared_ptr<KeyPair>, MaxKeypair> key_pairs;

  KeyManager(const std::filesystem::path &key_path);
};
#endif