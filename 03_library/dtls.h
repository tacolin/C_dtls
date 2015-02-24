#ifndef _DTLS_API_H_
#define _DTLS_API_H_

#include "basic.h"

#include <sys/un.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

////////////////////////////////////////////////////////////////////////////////

#define DTLS_OK   0
#define DTLS_FAIL -1
#define DTLS_END  0xabcd

#define BUFFER_SIZE ( 1 << 16 )
#define COOKIE_SECRET_LENGTH 16

#define DTLS_CLIENT_PEM_PATH "certs/client-cert.pem"
#define DTLS_CLIENT_KEY_PATH "certs/client-key.pem"
#define DTLS_CLIENT_DEFAULT_TIMEOUT 5

#define DTLS_SERVER_PEM_PATH "certs/server-cert.pem"
#define DTLS_SERVER_KEY_PATH "certs/server-key.pem"
#define DTLS_SERVER_DEFAULT_TIMEOUT 5

#define DTLS_CONNECTION_DEFAULT_TIMEOUT 1

////////////////////////////////////////////////////////////////////////////////

typedef union
{
    struct sockaddr_storage ss;
    struct sockaddr_in      s4;
    struct sockaddr_in6     s6;

} dtlsAddr;

typedef struct dtlsClient
{
    int fd;

    SSL_CTX* ctx;
    SSL*     ssl;
    BIO*     bio;

    dtlsAddr server_addr;
    struct timeval timeout;

    int is_started;

} dtlsClient;

typedef struct dtlsConnInfo
{
    SSL *ssl;
    BIO *bio;

    dtlsAddr client_addr;
    dtlsAddr local_addr;

    struct timeval timeout;

    void* server;

    struct dtlsConnInfo* next;

} dtlsConnInfo;

typedef struct dtlsServer
{
    /////////////////////////////////////////
    // unix domain socket
    /////////////////////////////////////////
    char               unpath[20];

    int                fd; // un server fd
    struct sockaddr_un un_server_addr;

    int                un_client_fd;
    struct sockaddr_un un_client_addr;

    /////////////////////////////////////////
    // DTLS (SSL)
    /////////////////////////////////////////
    int      dtls_fd;
    SSL_CTX* ctx;
    dtlsAddr   local_addr;

    int       is_started;
    pthread_t listen_thread;

    dtlsConnInfo* conn_list;

} dtlsServer;

////////////////////////////////////////////////////////////////////////////////

int dtls_initServer(const char* local_ip, const int local_port,
                     dtlsServer* server);
int dtls_uninitServer(dtlsServer* server);

int dtls_startServer(dtlsServer* server);
int dtls_stopServer(dtlsServer* server);

int dtls_recvData(dtlsServer* server, void* buffer, int buffer_size);

////////////////////////////////////////////////////////////////////////////////

int dtls_initClient(const char* remote_ip, int remote_port,
                     dtlsClient* client);
int dtls_uninitClient(dtlsClient* client);

int dtls_startCient(dtlsClient* client);
int dtls_stopClient(dtlsClient* client);

int dtls_sendData(dtlsClient* client, void* data, int data_len);

////////////////////////////////////////////////////////////////////////////////

int  dtls_initSystem(void);
void dtls_uninitSystem(void);

#endif //_DTLS_API_H_
