#include "connection.h"
#include <baSe/RAII.h>
#include <gnutls/gnutls.h>
#include <stdio.h>
#include <stdlib.h>
static void inbound_connection_deleter_(void *target_) {
  struct inbound_connection *target = target_;
  gnutls_deinit(target->local_session);
  close(target->local_socket);
}
static void connecting_connection_deleter_(void *target_) {
  struct connecting_connection *target = target_;
  atomic_fetch_sub(&target->local_keypair->references, 1);
  inbound_connection_deleter_(target_);
}
static void established_connection_deleter_(void *target_) {
  struct established_connection *target = target_;
  if (target->status >= ConnectionStatusRemoteHandshake)
    gnutls_deinit(target->remote_session);
  close(target->remote_socket);
  connecting_connection_deleter_(target_);
}
struct inbound_connection *createInboundConnection() {
  struct inbound_connection *result = malloc(sizeof(struct inbound_connection));
  RAII_set_deleter(result, inbound_connection_deleter_);
  return result;
}
struct connecting_connection *toConnectingConnection(struct inbound_connection *connection) {
  struct connecting_connection *result = realloc(connection, sizeof(struct connecting_connection));
  RAII_set_deleter(result, connecting_connection_deleter_);
  return result;
}
struct established_connection *toEstablishedConnection(struct connecting_connection *connection) {
  struct established_connection *result = realloc(connection, sizeof(struct established_connection));
  RAII_set_deleter(result, established_connection_deleter_);
  return result;
}