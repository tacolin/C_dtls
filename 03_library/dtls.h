#ifndef _DTLS_API_H_
#define _DTLS_API_H_

#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

////////////////////////////////////////////////////////////////////////////////

#define DTLS_SERVER_PEM_PATH "certs/server-cert.pem"
#define DTLS_SERVER_KEY_PATH "certs/server-key.pem"

////////////////////////////////////////////////////////////////////////////////

typedef enum
{
    DTLS_OK   = 0,
    DTLS_FAIL = -1

} dtlsStatus;

typedef enum
{
    DTLS_TRUE  = 1,
    DTLS_FALSE = 0

} dtlsBool;

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

    char* pem_path;
    char* key_path;

    dtlsAddr       server_addr;
    struct timeval timeout;

    dtlsBool       is_started;

} dtlsClient;

typedef struct dtlsConnInfo
{
    SSL *ssl;
    BIO *bio;

    dtlsAddr       client_addr;
    dtlsAddr       local_addr;
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
    dtlsAddr local_addr;

    struct timeval timeout;

    dtlsBool  is_started;
    pthread_t listen_thread;

    dtlsConnInfo* conn_list;

} dtlsServer;

////////////////////////////////////////////////////////////////////////////////

dtlsStatus dtls_initServer(const char* local_ip, const int local_port,
                           struct timeval timeout,
                           dtlsServer* server);

dtlsStatus dtls_uninitServer(dtlsServer* server);

dtlsStatus dtls_startServer(dtlsServer* server);
dtlsStatus dtls_stopServer(dtlsServer* server);

int dtls_recvData(dtlsServer* server, void* buffer, int buffer_size);

////////////////////////////////////////////////////////////////////////////////

dtlsStatus dtls_initClient(const char* remote_ip, int remote_port,
                           const char* pem_path, const char* key_path,
                           struct timeval timeout, dtlsClient* client);

dtlsStatus dtls_uninitClient(dtlsClient* client);

dtlsStatus dtls_startCient(dtlsClient* client);
dtlsStatus dtls_stopClient(dtlsClient* client);

int dtls_sendData(dtlsClient* client, void* data, int data_len);

////////////////////////////////////////////////////////////////////////////////

dtlsStatus  dtls_initSystem(void);
void        dtls_uninitSystem(void);

#endif //_DTLS_API_H_
