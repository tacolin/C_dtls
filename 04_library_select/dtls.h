#ifndef _DTLS_H_
#define _DTLS_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define DTLS_PATH_SIZE 108
#define DTLS_PORT_ANY -1
#define DTLS_OK (0)
#define DTLS_FAIL (-1)

struct dtls_addr
{
    char ipv4[INET_ADDRSTRLEN];
    int port;
};

struct dtls_server
{
    int fd;
    int local_port;
    int timeout_sec;
    char cert_path[DTLS_PATH_SIZE];
    char key_path[DTLS_PATH_SIZE];
    struct dtls_addr local;

    SSL_CTX* ctx;

    int is_init;
    int accept_run;
};

struct dtls
{
    int fd;
    int local_port;
    int timeout_sec;
    char cert_path[DTLS_PATH_SIZE];
    char key_path[DTLS_PATH_SIZE];
    struct dtls_addr remote;

    SSL_CTX* ctx;
    SSL* ssl;
    BIO* bio;

    int is_init;
};

int dtls_to_sockaddr(struct dtls_addr dtls_addr, struct sockaddr_in* sock_addr);
int dtls_to_dtlsaddr(struct sockaddr_in sock_addr, struct dtls_addr* dtls_addr);

int dtls_server_init(struct dtls_server* server, char* local_ip, int local_port, char* cert_path, char* key_path, int timeout_sec);
int dtls_server_uninit(struct dtls_server* server);
int dtls_server_accept(struct dtls_server* server, struct dtls* dtls);

int dtls_client_init(struct dtls* dtls, char* remote_ip, int remote_port, int local_port, char* cert_path, char* key_path, int timeout_sec);
int dtls_client_uninit(struct dtls* dtls);

int dtls_recv(struct dtls* dtls, void* buffer, int buffer_size);
int dtls_send(struct dtls* dtls, void* data, int data_len);

#endif //_DTLS_H_
