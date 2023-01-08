#define _GNU_SOURCE
#include "inbound.h"
#include "common.h"
#include "connection.h"
#include <baSe/list.h>
#include <baSe/hashtable.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include <assert.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pthread.h>
static const char* DefaultPriorityString = "SECURE192:-VERS-ALL:+VERS-TLS1.2:+VERS-TLS1.3";
List inbound;
struct certificate_table certificate_table;
bool session_lookup_comparator(const void* data, const void* rhs){
    return *(gnutls_session_t*)data == ((struct inbound_connection*)rhs)->local_session;
}
static int cert_callback(
    gnutls_session_t session,
    const gnutls_datum_t * req_ca_rdn,
    int nreqs,
    const gnutls_pk_algorithm_t * sign_algos,
    int sign_algos_length,
    gnutls_pcert_st ** pcert,
    unsigned int *pcert_length,
    gnutls_privkey_t * pkey
){
    ListNode* node = List_find(&inbound, &session, session_lookup_comparator);
    if(node == NULL) return 1;
    int ret;
    char name_buffer[1000];
    size_t length = 1000;
    unsigned int type;
    ret = gnutls_server_name_get(session, name_buffer, &length, &type, 0);
    if(ret == GNUTLS_E_SUCCESS && type == GNUTLS_NAME_DNS){
        printf("decoded: %s\n", name_buffer);
        struct keypair* keypair = certificate_table_prepare(&certificate_table, name_buffer);
        if(keypair == NULL) return 1;
        struct connecting_connection* connection = toConnectingConnection(node->data);
        node->data = connection;
        connection->local_keypair = keypair;
        *pcert = &keypair->cert;
        *pcert_length = 1;
        *pkey = keypair->key;
        return 0;
    }else{
        if(ret != GNUTLS_E_SUCCESS) fprintf(stderr, "failed to get SNI: %s\n", gnutls_strerror(ret));
        else fprintf(stderr, "unrecognized SNI type: %d\n", type);
        return 1;
    }
}
void* inbound_entry(void* arg){
    struct inbound_parameter* parameters = arg;
    int optval = 1;
    gnutls_certificate_credentials_t x509_cred;
    CHECK(gnutls_certificate_allocate_credentials(&x509_cred));
    gnutls_certificate_set_retrieve_function2(x509_cred, cert_callback);
    List_initialize(&inbound);
    certificate_table_init(&certificate_table, 19);
    int listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    memset(&server_address, '\0', sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_address.sin_port = htons(443);
    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, (void *) &optval, sizeof(int));
    if(bind(listen_socket, (struct sockaddr *) &server_address, sizeof(server_address)) == -1){
        perror("bind");
        pthread_exit(NULL);
    }
    listen(listen_socket, 1024);
    socklen_t client_length = sizeof(client_address);
    int connected_socket;
    int ret;
    while(true){
        connected_socket = accept(listen_socket, (struct sockaddr *)&client_address, &client_length);
        struct inbound_connection* i_connection = createInboundConnection();
        CHECK(gnutls_init(&i_connection->local_session, GNUTLS_SERVER | GNUTLS_AUTO_REAUTH));
        CHECK(gnutls_priority_set_direct(i_connection->local_session, DefaultPriorityString, NULL));
        CHECK(gnutls_credentials_set(i_connection->local_session, GNUTLS_CRD_CERTIFICATE, x509_cred));
        gnutls_certificate_server_set_request(i_connection->local_session, GNUTLS_CERT_IGNORE);
        gnutls_handshake_set_timeout(i_connection->local_session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
        i_connection->local_socket = connected_socket;
        i_connection->status = ConnectionStatusInbound;
        gnutls_transport_set_int(i_connection->local_session, i_connection->local_socket);
        ListNode* node = List_emplace_back(&inbound, ListNode_create(i_connection, true));
        LOOP_CHECK(ret, gnutls_handshake(i_connection->local_session));
        if (ret < 0) {
            fprintf(stderr, "*** Handshake has failed (%s)\n\n", gnutls_strerror(ret));
            continue;
        }
        printf("- Handshake was completed\n");
        struct connecting_connection* c_connection = node->data;
        c_connection->status = ConnectionStatusConnecting;
        List_detach(&inbound, node);
        do{
            ret = write(parameters->pipe_to_next, &node, sizeof(node));
        }while(ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
        fprintf(stderr, "inbound: handed to next stage\n");
    }
    close(listen_socket);
    gnutls_certificate_free_credentials(x509_cred);
    pthread_exit(NULL);
}