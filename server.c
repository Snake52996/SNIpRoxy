#include <errno.h>
#define _GNU_SOURCE
#include "server.h"
#include "connection.h"
#include <baSe/list.h>
#include <sys/epoll.h>
#include <gnutls/gnutls.h>
#include <pthread.h>
#define gnutlsCall(call,rtv,msg) do{\
    if(((rtv)=(call))<0){\
        fprintf(stderr,"%s: %s\n",(msg),gnutls_strerror(rtv));\
        exit(EXIT_FAILURE);\
    }\
}while(0)
#define LOOP_CHECK(rval, cmd) do{\
    rval = cmd;\
}while(rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)
static const char* DefaultPriorityString = 
    "NONE:+VERS-TLS1.3:+COMP-ALL:+AEAD:+CTYPE-X509:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305"
    ":+GROUP-SECP256R1:+GROUP-SECP384R1:+GROUP-SECP521R1:+GROUP-X25519:+SIGN-RSA-PSS-RSAE-SHA256"
    ":+SIGN-RSA-PSS-RSAE-SHA384:+SIGN-RSA-PSS-RSAE-SHA512:+SIGN-EdDSA-Ed25519:%PROFILE_MEDIUM";
static bool doHandshake(void* data, struct established_connection* e_connection, int epfd){
    fprintf(stderr, "server: handshaking for %s\n", e_connection->local_keypair->hostname);
    int rtv;
    do{
        rtv = gnutls_handshake(e_connection->remote_session);
    }while(rtv < 0 && gnutls_error_is_fatal(rtv) == 0);
    if(rtv >= 0){
        e_connection->status = ConnectionStatusEstablished;
        struct epoll_event ev;
        ev.events = EPOLLERR | EPOLLIN;
        ev.data.ptr = (uintmax_t)data | 1;
        epoll_ctl(epfd, EPOLL_CTL_ADD, e_connection->local_socket, &ev);
        fprintf(stderr, "server: handshaking for %s succeed\n", e_connection->local_keypair->hostname);
    }else if(gnutls_error_is_fatal(rtv) != 0){
        fprintf(stderr, "server: handshaking for %s fatal\n", e_connection->local_keypair->hostname);
        fprintf(stderr, "server: handshake error: %s\n", gnutls_strerror(rtv));
        return true;
    }
    return false;
}
static bool initializeHandshake(
    void* data, struct established_connection* e_connection, gnutls_certificate_credentials_t xcred, int epfd
){
    fprintf(stderr, "initializing handshake for %s\n", e_connection->local_keypair->hostname);
    do{
        if(gnutls_init(
            &e_connection->remote_session,
            GNUTLS_CLIENT | GNUTLS_NO_AUTO_SEND_TICKET | GNUTLS_AUTO_REAUTH | GNUTLS_POST_HANDSHAKE_AUTH | GNUTLS_NONBLOCK
        ) < 0) break;
        if(gnutls_priority_set_direct(e_connection->remote_session, DefaultPriorityString, NULL) < 0) break;
        if(gnutls_credentials_set(e_connection->remote_session, GNUTLS_CRD_CERTIFICATE, xcred) < 0) break;
        gnutls_session_set_verify_cert(
            e_connection->remote_session, e_connection->local_keypair->hostname, 0);
        gnutls_handshake_set_timeout(e_connection->remote_session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
        gnutls_transport_set_int(e_connection->remote_session, e_connection->remote_socket);
        e_connection->status = ConnectionStatusRemoteHandshake;
        if(doHandshake(data, e_connection, epfd)) break;
        return false;
    }while(false);
    return true;
}
static bool receiveConnection(List* list, int receive_fd, int epfd, gnutls_certificate_credentials_t xcred){
    struct epoll_event ev;
    ev.events = EPOLLERR | EPOLLIN;
    ssize_t read_count;
    ListNode* node;
    while(true){
        read_count = read(receive_fd, &node, sizeof(node));
        if(read_count != sizeof(node)){
            if(read_count == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)){
                return false;
            }else{
                return true;
            }
        }
        fprintf(stderr, "server: connection received\n");
        List_emplace_back(list, node);
        ev.data.ptr = node;
        epoll_ctl(epfd, EPOLL_CTL_ADD, ((struct established_connection*)node->data)->remote_socket, &ev);
        initializeHandshake(node, node->data, xcred, epfd);
    }
}
void* server_entry(void* arg){
    int rtv;
    enum{ EpollEvents = 32, BufferSize = 0x10000 };
    struct server_parameter* parameters = arg;
    List established;
    List disconnecting;
    List_initialize(&established);
    List_initialize(&disconnecting);
    gnutls_certificate_credentials_t xcred;
    gnutlsCall(gnutls_certificate_allocate_credentials(&xcred), rtv, "allocate for certificate");
    gnutlsCall(gnutls_certificate_set_x509_system_trust(xcred), rtv, "load default certificate");
    int epfd = epoll_create1(0);
    struct epoll_event ev, events[EpollEvents];
    ev.events = EPOLLHUP | EPOLLERR | EPOLLIN | EPOLLET;
    ev.data.fd = parameters->pipe_from_last;
    epoll_ctl(epfd, EPOLL_CTL_ADD, parameters->pipe_from_last, &ev);
    char buffer[BufferSize];
    ssize_t read_size;
    while(true){
        int fds = epoll_wait(epfd, events, EpollEvents, -1);
        for(int i = 0; i < fds; i++){
            if(events[i].data.fd == parameters->pipe_from_last){
                receiveConnection(&established, parameters->pipe_from_last, epfd, xcred);
                continue;
            }
            ListNode* node = ((uintmax_t)events[i].data.ptr | 1) - 1;
            struct established_connection* e_connection = node->data;
            if(e_connection->status == ConnectionStatusDisconnecting) continue;
            if(events[i].events & EPOLLERR){
                List_detach(&established, node);
                List_emplace_back(&disconnecting, node);
                e_connection->status = ConnectionStatusDisconnecting;
                continue;
            }
            if(events[i].events & EPOLLIN){
                if(e_connection->status == ConnectionStatusConnecting){
                    if(initializeHandshake(node, e_connection, xcred, epfd)){
                        List_detach(&established, node);
                        List_emplace_back(&disconnecting, node);
                        e_connection->status = ConnectionStatusDisconnecting;
                    }
                }else if(e_connection->status == ConnectionStatusRemoteHandshake){
                    if(doHandshake(node, e_connection, epfd)){
                        List_detach(&established, node);
                        List_emplace_back(&disconnecting, node);
                        e_connection->status = ConnectionStatusDisconnecting;
                    }
                }else if(e_connection->status == ConnectionStatusEstablished){
                    if((uintmax_t)events[i].data.ptr & 1){
                        LOOP_CHECK(read_size, gnutls_record_recv(e_connection->local_session, buffer, BufferSize));
                        if(read_size <= 0){
                            List_detach(&established, node);
                            List_emplace_back(&disconnecting, node);
                            e_connection->status = ConnectionStatusDisconnecting;
                            continue;
                        }
                        fprintf(stderr, "server: %ld bytes from local session\n", read_size);
                        LOOP_CHECK(rtv, gnutls_record_send(e_connection->remote_session, buffer, read_size));
                        if(rtv <= 0){
                            List_detach(&established, node);
                            List_emplace_back(&disconnecting, node);
                            e_connection->status = ConnectionStatusDisconnecting;
                            continue;
                        }
                    }else{
                        LOOP_CHECK(read_size, gnutls_record_recv(e_connection->remote_session, buffer, BufferSize));
                        if(read_size <= 0){
                            List_detach(&established, node);
                            List_emplace_back(&disconnecting, node);
                            e_connection->status = ConnectionStatusDisconnecting;
                            continue;
                        }
                        fprintf(stderr, "server: %ld bytes from remote session\n", read_size);
                        LOOP_CHECK(rtv, gnutls_record_send(e_connection->local_session, buffer, read_size));
                        if(rtv <= 0){
                            List_detach(&established, node);
                            List_emplace_back(&disconnecting, node);
                            e_connection->status = ConnectionStatusDisconnecting;
                            continue;
                        }
                    }
                }
            }
        }
        List_clear(&disconnecting);
    }
    close(epfd);
    List_clear(&established);
    gnutls_certificate_free_credentials(xcred);
    pthread_exit(NULL);
}