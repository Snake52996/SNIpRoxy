#ifndef SNIPROXY_CA_H_
#define SNIPROXY_CA_H_
#include <gnutls/x509.h>
void generate_certificate(const char* hostname, gnutls_x509_crt_t* cert, gnutls_x509_privkey_t* key);
#endif