#include "ca.h"
#include <errno.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509-ext.h>
#include <gnutls/x509.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static const char *CACertificateName = "ca-cert.pem";
static const char *CAKeyName = "ca-key.pem";
static const gnutls_pk_algorithm_t Algorithm = GNUTLS_PK_ECDSA;
static const time_t CAExpirationSeconds = 60l * 60 * 24 * 360 * 2;
enum { SerialLength = 20 };
static gnutls_x509_crt_t ca_cert;
static gnutls_x509_privkey_t ca_key;
static bool prepared = false;
static void build_serial(char *serial_buffer) {
  getrandom(serial_buffer, SerialLength, 0);
  serial_buffer[0] &= (unsigned char)(((unsigned char)-1) << 1) >> 1;
}
static void write_buffer(const char *filename, gnutls_datum_t *buffer) {
  int fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
  write(fd, buffer->data, buffer->size);
  close(fd);
}
static void read_buffer(const char *filename, gnutls_datum_t *buffer) {
  struct stat status;
  stat(filename, &status);
  buffer->data = malloc(status.st_size);
  buffer->size = status.st_size;
  int fd = open(filename, O_RDONLY);
  read(fd, buffer->data, buffer->size);
  close(fd);
}
static inline unsigned char to_hex(unsigned int value) {
  value &= 0xf;
  return value >= 10 ? 'a' + value - 10 : '0' + value;
}
static unsigned char *get_certificate_fingerprint(gnutls_x509_crt_t *cert) {
  size_t length;
  gnutls_x509_crt_get_fingerprint(*cert, GNUTLS_DIG_SHA256, NULL, &length);
  char *temporary_buffer = malloc(length);
  gnutls_x509_crt_get_fingerprint(*cert, GNUTLS_DIG_SHA256, temporary_buffer, &length);
  unsigned char *buffer = malloc((length << 1) + 1);
  for (size_t i = 0; i < length; i++) {
    buffer[i << 1] = to_hex(temporary_buffer[i] >> 4);
    buffer[(i << 1) | 1] = to_hex(temporary_buffer[i] & 0xf);
  }
  buffer[length << 1] = '\0';
  free(temporary_buffer);
  return buffer;
}
static void generate_general_certificate(
    gnutls_x509_crt_t *cert, gnutls_x509_privkey_t *key, gnutls_sec_param_t parameter
) {
  char serial_buffer[SerialLength];
  gnutls_x509_crt_init(cert);
  gnutls_x509_privkey_init(key);
  gnutls_x509_privkey_generate(*key, Algorithm, gnutls_sec_param_to_pk_bits(Algorithm, parameter), 0);
  gnutls_x509_crt_set_version(*cert, 3);
  gnutls_x509_crt_set_activation_time(*cert, time(NULL));
  gnutls_x509_crt_set_key(*cert, *key);
  build_serial(serial_buffer);
  gnutls_x509_crt_set_serial(*cert, serial_buffer, SerialLength);
}
static void
generate_ca_certificate(gnutls_x509_crt_t *cert, gnutls_x509_privkey_t *key, gnutls_sec_param_t parameter) {
  static const char CommonName[] = "SNIpRoxy CA";
  generate_general_certificate(cert, key, parameter);
  gnutls_x509_crt_set_basic_constraints(*cert, 1, 1);
  gnutls_x509_crt_set_dn_by_oid(*cert, GNUTLS_OID_X520_COMMON_NAME, 0, CommonName, sizeof(CommonName) - 1);
  gnutls_x509_crt_set_key_usage(*cert, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_CERT_SIGN);
  gnutls_x509_crt_set_expiration_time(*cert, time(NULL) + CAExpirationSeconds);
  gnutls_x509_crt_sign(*cert, *cert, *key);
}
static void generate_ssl_certificate(
    const char *hostname, gnutls_x509_crt_t *cert, gnutls_x509_privkey_t *key, gnutls_sec_param_t parameter
) {
  generate_general_certificate(cert, key, parameter);
  gnutls_x509_crt_set_basic_constraints(*cert, 0, -1);
  gnutls_x509_crt_set_subject_alternative_name(*cert, GNUTLS_SAN_DNSNAME, hostname);
  gnutls_x509_crt_set_key_purpose_oid(*cert, GNUTLS_KP_TLS_WWW_SERVER, 1);
  gnutls_x509_crt_set_key_usage(*cert, GNUTLS_KEY_DIGITAL_SIGNATURE);
  gnutls_x509_crt_set_expiration_time(*cert, time(NULL) + 60l * 60 * 24 * 2);
  gnutls_x509_crt_sign(*cert, ca_cert, ca_key);
}
static void generate_ca() {
  gnutls_x509_crt_t temp_cert;
  gnutls_x509_privkey_t temp_key;
  generate_ca_certificate(&temp_cert, &temp_key, GNUTLS_SEC_PARAM_FUTURE);
  gnutls_datum_t buffer;
  gnutls_x509_crt_export2(temp_cert, GNUTLS_X509_FMT_PEM, &buffer);
  write_buffer(CACertificateName, &buffer);
  gnutls_free(buffer.data);
  gnutls_x509_privkey_export2(temp_key, GNUTLS_X509_FMT_PEM, &buffer);
  write_buffer(CAKeyName, &buffer);
  gnutls_free(buffer.data);
  gnutls_x509_privkey_deinit(temp_key);
  size_t length = 64;
  char *path = malloc(length);
  while (true) {
    if (getcwd(path, length) != NULL)
      break;
    if (errno != ERANGE) {
      strcpy(path, "<unknown current working directory>");
      break;
    }
    length <<= 1;
    free(path);
    path = malloc(length);
  }
  unsigned char *fingerprint = get_certificate_fingerprint(&temp_cert);
  gnutls_x509_crt_deinit(temp_cert);
  printf(
      "ca: a new CA certificate is generated, fingerprint: %s\n"
      " The certificate has been exported as %s/%s\n"
      "  you may need to add it to your system/application trust list\n"
      " This happens due to absence or expiration of CA certificate and/or key. If which is not expected,\n"
      "  verifying file location and permissions may help.\n",
      fingerprint, path, CACertificateName
  );
  free(path);
  free(fingerprint);
}
static void free_ca() {
  gnutls_x509_crt_deinit(ca_cert);
  gnutls_x509_privkey_deinit(ca_key);
}
static bool load_ca() {
  if (access(CACertificateName, R_OK) != 0 || access(CAKeyName, R_OK))
    return false;
  gnutls_datum_t buffer;
  read_buffer(CACertificateName, &buffer);
  gnutls_x509_crt_import(ca_cert, &buffer, GNUTLS_X509_FMT_PEM);
  free(buffer.data);
  read_buffer(CAKeyName, &buffer);
  gnutls_x509_privkey_import(ca_key, &buffer, GNUTLS_X509_FMT_PEM);
  free(buffer.data);
  return true;
}
static bool prepare_ca() {
  if (prepared)
    return true;
  gnutls_x509_crt_init(&ca_cert);
  gnutls_x509_privkey_init(&ca_key);
  if (!load_ca())
    generate_ca();
  if (!load_ca()) {
    fprintf(stderr, "ca: failed to prepare CA certificate\n");
    return false;
  }
  unsigned char *fingerprint = get_certificate_fingerprint(&ca_cert);
  printf("ca: loaded CA certificate, fingerprint: %s\n", fingerprint);
  free(fingerprint);
  atexit(free_ca);
  prepared = true;
  return true;
}
void generate_certificate(const char *hostname, gnutls_x509_crt_t *cert, gnutls_x509_privkey_t *key) {
  if (!prepared)
    prepare_ca();
  generate_ssl_certificate(hostname, cert, key, GNUTLS_SEC_PARAM_ULTRA);
}