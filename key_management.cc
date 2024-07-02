#include "key_management.hh"
#include "common.hh"

#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <mutex>
#include <sys/random.h>
#include <unistd.h>
#include <unordered_map>
namespace {
// logging
static LogPP::Logger *logger;
static LogPP::Logger *performance_logger;
static bool           initialize() {
  static auto logger_ = LogPP::logger.create_sub_logger("key_management");
  logger              = &logger_;

  static auto performance_logger_ = global_loggers->performance_logger->create_sub_logger("key_management");
  performance_logger = &performance_logger_;

  logger->information("key management system initialized");
  return true;
}

// key management

// constants
// length of serial number in certificates
constexpr size_t                SerialLength            = 20;
// algorithm to use in key pairs
constexpr gnutls_pk_algorithm_t Algorithm               = GNUTLS_PK_ECDSA;
// the CA certificate shall be valid for two years
constexpr time_t                CAExpirationSeconds     = 60l * 60 * 24 * 360 * 2;
// the certificate used by server shall be valid for two days
constexpr time_t                ServerExpirationSeconds = 60l * 60 * 24 * 2;
// margin time, certificate that will expire within 30 mins shall be considered as already expired
constexpr time_t                MarginSeconds           = 60l * 30;

// generate random serial number
static std::array<uint8_t, SerialLength> generate_serial_number() {
  std::array<uint8_t, SerialLength> serial_number;
  // get a random number
  ::getrandom(serial_number.data(), serial_number.size(), 0);
  // clear the left most bit as per requirement by the X.509/PKIX specifications
  serial_number[0] &= static_cast<uint8_t>(static_cast<uint8_t>(-1) << 1) >> 1;
  return serial_number;
}

// write data in gnutls_datum_t buffer into file referred by path
//  return true if failure occurred, false otherwise
static bool operator<<(const std::filesystem::path &path, const gnutls_datum_t &buffer) {
  // content of these files should be kept secret, especially the private key
  //  creating them with restricted permission adds an extra layer of security anyway
  int file = 0;
  file     = open(path.c_str(), O_CLOEXEC | O_CREAT | O_EXCL | O_WRONLY, 0600);
  if (file == -1) {
    logger->error("cannot open {} for writing gnutls buffer content: {}", path.c_str(), strerror(errno));
    return true;
  }
  if (write(file, buffer.data, buffer.size) != buffer.size) {
    logger->error(
      "incomplete write of gnutls buffer content to {}, this may be helpful: {}",
      path.c_str(),
      strerror(errno)
    );
    return true;
  }
  close(file);
  return false;
}

// read data to gnutls_datum_t buffer from file referred by path
static void operator>>(const std::filesystem::path &path, gnutls_datum_t &buffer) {
  if (buffer.data != nullptr) {
    ::free(buffer.data);
  }
  buffer.size = std::filesystem::file_size(path);
  buffer.data = reinterpret_cast<unsigned char *>(::malloc(buffer.size));
  std::ifstream input(path, std::ios::in | std::ios::binary);
  input.read(reinterpret_cast<char *>(buffer.data), buffer.size);
}

// check permission of file
//  warn about it if the permission is not 0600
static void check_permission(const std::filesystem::path &path) {
  auto permission         = std::filesystem::status(path).permissions();
  auto numeric_permission = static_cast<uint32_t>(permission);
  if (numeric_permission != 0600) {
    logger->warning(
      "{} have insecure permission value {:o} while 0600 is expected", path.c_str(), numeric_permission
    );
  }
}

// get fingerprints of a certificate
static std::unordered_map<std::string_view, std::string> get_certificate_fingerprint(gnutls_x509_crt_t cert) {
  // list types of digest that should be calculated
  constexpr auto algorithms = std::to_array<std::pair<gnutls_digest_algorithm_t, const char *>>({
    {GNUTLS_DIG_SHA1, "SHA1"},
    {GNUTLS_DIG_SHA256, "SHA256"},
  });

  constexpr auto to_hex = [](unsigned int value) -> unsigned char {
    value &= 0xf;
    return value >= 10 ? 'a' + value - 10 : '0' + value;
  };

  std::unordered_map<std::string_view, std::string> result;
  for (const auto [algorithm, name] : algorithms) {
    size_t length;
    // query length
    gnutls_x509_crt_get_fingerprint(cert, algorithm, NULL, &length);
    // make buffer for result
    std::string digest(length, '\0');
    // query result
    int         return_value = gnutls_x509_crt_get_fingerprint(cert, algorithm, digest.data(), &length);
    if (return_value != GNUTLS_E_SUCCESS) {
      // log an error and replace the result with placeholder
      logger->error("failed to calculate {} digest for certificate: {}", name, gnutls_strerror(return_value));
      digest = "<UNAVAILABLE>";
    } else {
      // hex encode the digest thus making it human-readable
      std::string buffer(length * 2, '\0');
      for (size_t i = 0, j = 0; i < digest.size(); i++) {
        buffer[j++] = to_hex(digest[i] >> 4);
        buffer[j++] = to_hex(digest[i] & 0xf);
      }
      digest = std::move(buffer);
    }
    result.emplace(name, std::move(digest));
  }
  return result;
}

// generate a general purposed certificate and private key
static std::pair<gnutls_x509_crt_t, gnutls_x509_privkey_t>
generate_general_certificate(gnutls_sec_param_t parameter) {
  gnutls_x509_crt_t     cert;
  gnutls_x509_privkey_t key;
  // initialize the contexts
  assert_gnutls_call(gnutls_x509_crt_init, &cert);
  assert_gnutls_call(gnutls_x509_privkey_init, &key);

  // generate private key with respect to the security requirement parameter
  assert_gnutls_call(
    gnutls_x509_privkey_generate, key, Algorithm, gnutls_sec_param_to_pk_bits(Algorithm, parameter), 0
  );
  // set certification version to 3
  assert_gnutls_call(gnutls_x509_crt_set_version, cert, 3);
  // make the certification valid immediately
  assert_gnutls_call(gnutls_x509_crt_set_activation_time, cert, time(NULL));
  // assign the private key to the certification
  assert_gnutls_call(gnutls_x509_crt_set_key, cert, key);

  // set serial number
  auto serial_number = generate_serial_number();
  assert_gnutls_call(gnutls_x509_crt_set_serial, cert, serial_number.data(), serial_number.size());
  return {cert, key};
}

// generate a certificate and a private key that can be used by a server implemented TLS with hostname
static std::pair<gnutls_x509_crt_t, gnutls_x509_privkey_t>
generate_ssl_keypair(std::string_view hostname, gnutls_sec_param_t parameter) {
  auto [cert, key] = generate_general_certificate(parameter);

  // mark this certificate as not held by a CA and may only be the ending node on a certificate chain
  gnutls_x509_crt_set_basic_constraints(cert, 0, -1);
  // associate the certificate with the DNS name, i.e. host name
  gnutls_x509_crt_set_subject_alternative_name(cert, GNUTLS_SAN_DNSNAME, hostname.data());
  // mark it as being used by a TLS server
  gnutls_x509_crt_set_key_purpose_oid(cert, GNUTLS_KP_TLS_WWW_SERVER, 1);
  // make the certificate only usable for creating digital signatures
  gnutls_x509_crt_set_key_usage(cert, GNUTLS_KEY_DIGITAL_SIGNATURE);
  // setup expiration time
  gnutls_x509_crt_set_expiration_time(cert, time(NULL) + ServerExpirationSeconds);
  return {cert, key};
}

// generate a certificate and a private key that can be used by a CA
static std::pair<gnutls_x509_crt_t, gnutls_x509_privkey_t> generate_ca_keypair(gnutls_sec_param_t parameter) {
  constexpr std::string_view CommonName{"SNIpRoxy CA"};

  auto [cert, key] = generate_general_certificate(parameter);
  // make the certificate corresponding to a CA and limit the length of valid certificate chain to 1
  //  this is because we will always sign TLS certificate directly with this CA keypair
  assert_gnutls_call(gnutls_x509_crt_set_basic_constraints, cert, 1, 1);
  // set common name of the certificate
  assert_gnutls_call(
    gnutls_x509_crt_set_dn_by_oid, cert, GNUTLS_OID_X520_COMMON_NAME, 0, CommonName.data(), CommonName.size()
  );
  // make the certificate usable for digital signing and key pair signing, which is required for a keypair to
  //  be used by a CA
  assert_gnutls_call(
    gnutls_x509_crt_set_key_usage, cert, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_CERT_SIGN
  );
  // setup expiration time
  assert_gnutls_call(gnutls_x509_crt_set_expiration_time, cert, time(NULL) + CAExpirationSeconds);
  // self-sign the certificate
  assert_gnutls_call(gnutls_x509_crt_sign, cert, cert, key);
  return {cert, key};
}

// export certificate file and private key file to specified path
static void export_keypair(
  gnutls_x509_crt_t            cert,
  const std::filesystem::path &certificate_path,
  gnutls_x509_privkey_t        key,
  const std::filesystem::path &key_path
) {
  gnutls_datum_t buffer;
  assert_gnutls_call(gnutls_x509_crt_export2, cert, GNUTLS_X509_FMT_PEM, &buffer);
  if (certificate_path << buffer) {
    logger->critical("failed to save CA certificate, see error above");
    ::exit(EXIT_FAILURE);
  }
  // data in buffer is allocated dynamically and we should take care freeing them
  gnutls_free(buffer.data);

  assert_gnutls_call(gnutls_x509_privkey_export2, key, GNUTLS_X509_FMT_PEM, &buffer);
  if (key_path << buffer) {
    logger->critical("failed to save CA private key, see error above");
    ::exit(EXIT_FAILURE);
  }
  gnutls_free(buffer.data);
}

}; // namespace

// implements of exported interfaces

KeyPair::~KeyPair() {
  gnutls_pcert_deinit(&this->cert);
  gnutls_privkey_deinit(this->key);
}

KeyManager::~KeyManager() {
  gnutls_x509_privkey_deinit(this->ca_key);
  gnutls_x509_crt_deinit(this->ca_cert);
}

KeyManager &KeyManager::get_manager(const std::filesystem::path &key_path) {
  static bool                                                              initialize_helper = initialize();
  static std::unordered_map<std::string_view, std::unique_ptr<KeyManager>> instance_map;
  static std::mutex                                                        mutex;

  // since modifications may take place here, we need a lock
  performance_logger->trace("acquiring lock in get_manager...");
  std::lock_guard lock(mutex);
  performance_logger->trace("lock acquired in get_manager");
  KeyManager *result      = nullptr;
  auto        find_result = instance_map.find(key_path.string());
  if (find_result != instance_map.cend()) {
    result = find_result->second.get();
  } else {
    result = new KeyManager(key_path);
    instance_map.emplace(key_path.string(), result);
  }
  performance_logger->trace("lock released in get_manager");
  return *result;
}

std::shared_ptr<KeyPair> KeyManager::get_key_pair(std::string_view hostname) {
  return this->key_pairs.get(
    std::string(hostname),
    [](const std::shared_ptr<KeyPair> &key_pair) -> bool {
      // check if this certificate is still valid at this moment
      gnutls_x509_crt_t cert;
      gnutls_pcert_export_x509(&key_pair->cert, &cert);
      auto expiration_time = gnutls_x509_crt_get_expiration_time(cert);
      gnutls_x509_crt_deinit(cert);
      return expiration_time > time(NULL) + MarginSeconds;
    },
    [hostname, this]() -> std::shared_ptr<KeyPair> {
      logger->trace("generate new certificate for {}", hostname);
      // build a key pair
      auto [cert, key] = generate_ssl_keypair(hostname, GNUTLS_SEC_PARAM_ULTRA);
      // sign it with private key of CA
      gnutls_x509_crt_sign(cert, this->ca_cert, this->ca_key);
      auto keypair      = std::make_shared<KeyPair>();
      // store hostname
      keypair->hostname = hostname;
      // build a gnutls_pcert_st instance from the certificate
      gnutls_pcert_import_x509(&keypair->cert, cert, 0);
      // and build a gnutls_privkey_t instance from the private key
      gnutls_privkey_init(&keypair->key);
      gnutls_privkey_import_x509(keypair->key, key, GNUTLS_PRIVKEY_IMPORT_COPY);
      // free contexts that is no longer needed
      gnutls_x509_crt_deinit(cert);
      gnutls_x509_privkey_deinit(key);
      return std::move(keypair);
    }
  );
}
void KeyManager::reload() {
  // since CA keypair may be reloaded, we should clear cache to avoid mismatching
  this->key_pairs.clear();

  // check if the directory exist or is usable
  logger->trace("constructing key manager on path {}", this->key_path.c_str());
  auto directory_status = std::filesystem::status(this->key_path);
  if (!std::filesystem::exists(directory_status)) {
    logger->information("creating non-existing directory {}", this->key_path.c_str());
    std::filesystem::create_directories(this->key_path);
  } else if (!std::filesystem::is_directory(directory_status)) {
    logger->critical("{} exists but is not a directory!", this->key_path.c_str());
    ::exit(EXIT_FAILURE);
  }

  // check if the keys exists
  auto certificate_path = this->key_path / "ca-cert.pem";
  auto private_key_path = this->key_path / "ca-key.pem";
  if (!std::filesystem::exists(certificate_path) || !std::filesystem::exists(private_key_path)) {
    logger->information("key pair of CA does not exist or is incomplete, regenerating them...");
    try {
      std::filesystem::remove_all(certificate_path);
      std::filesystem::remove_all(private_key_path);
    } catch (...) {
    }
    performance_logger->trace("generating CA keypair...");
    auto [cert, key] = generate_ca_keypair(GNUTLS_SEC_PARAM_FUTURE);
    performance_logger->trace("CA keypair generated");
    export_keypair(cert, certificate_path, key, private_key_path);
    gnutls_x509_privkey_deinit(key);
    // show fingerprint and give instruct on actions must be taken to make the new CA certificate work
    auto fingerprints = get_certificate_fingerprint(cert);
    gnutls_x509_crt_deinit(cert);
    logger->information(
      ">>> new CA certificate is generated <<<\n"
      " fingerprints are:\n"
      "  SHA1: {}\n"
      "  SHA256: {}\n"
      " The certificate has been exported as\n"
      "  {}\n"
      " you may need to add it to your system/application trust list before you can use it",
      fingerprints.at("SHA1"),
      fingerprints.at("SHA256"),
      certificate_path.c_str()
    );
  }

  // load the keys as CA keypair
  //  do permission check and warn for insecure permissions
  check_permission(certificate_path);
  check_permission(private_key_path);
  //  anyway, load them in
  gnutls_datum_t buffer{nullptr, 0};
  certificate_path >> buffer;
  assert_gnutls_call(gnutls_x509_crt_import, this->ca_cert, &buffer, GNUTLS_X509_FMT_PEM);
  // no need to free here: operator>> does that for us
  private_key_path >> buffer;
  assert_gnutls_call(gnutls_x509_privkey_import, this->ca_key, &buffer, GNUTLS_X509_FMT_PEM);
  ::free(buffer.data);
  buffer.data = nullptr;

  // show fingerprint of the loaded certificate so that the user have a chance to notice it in case
  //  an irregular certificate is loaded
  auto fingerprints = get_certificate_fingerprint(this->ca_cert);
  logger->information(
    "CA certificate loaded\n"
    " fingerprints are:\n"
    "  SHA1: {}\n"
    "  SHA256: {}\n",
    fingerprints.at("SHA1"),
    fingerprints.at("SHA256")
  );

  // clear cache
  this->clear();
}
void KeyManager::clear() { this->key_pairs.clear(); }

KeyManager::KeyManager(const std::filesystem::path &key_path) : key_path(key_path) {
  // initializes shall be done here
  assert_gnutls_call(gnutls_x509_crt_init, &this->ca_cert);
  assert_gnutls_call(gnutls_x509_privkey_init, &this->ca_key);
  this->reload();
}