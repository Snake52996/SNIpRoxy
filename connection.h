#ifndef SNIPROXY_CONNECTION_H_
#define SNIPROXY_CONNECTION_H_
#include "keypair.h"
#include <baSe/RAII.h>
enum connection_status {
  ConnectionStatusInbound,
  ConnectionStatusConnecting,
  ConnectionStatusRemoteHandshake,
  ConnectionStatusEstablished,
  ConnectionStatusDisconnecting,
};
struct connection {
  RAII _;
  enum connection_status status;
};
struct inbound_connection {
  RAII _;
  enum connection_status status;
  int local_socket;
  gnutls_session_t local_session;
};
struct connecting_connection {
  RAII _;
  enum connection_status status;
  int local_socket;
  gnutls_session_t local_session;
  struct keypair *local_keypair;
};
struct established_connection {
  RAII _;
  enum connection_status status;
  int local_socket;
  gnutls_session_t local_session;
  struct keypair *local_keypair;
  int remote_socket;
  gnutls_session_t remote_session;
};
struct inbound_connection *createInboundConnection();
struct connecting_connection *toConnectingConnection(struct inbound_connection *connection);
struct established_connection *toEstablishedConnection(struct connecting_connection *connection);
#endif