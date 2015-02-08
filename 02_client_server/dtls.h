#ifndef _DTLS_API_H_
#define _DTLS_API_H_

#include "basic.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

////////////////////////////////////////////////////////////////////////////////

#define DTLS_OK   OK
#define DTLS_FAIL FAIL
#define DTLS_END  0xabcd

#define BUFFER_SIZE ( 1 << 16 )
#define COOKIE_SECRET_LENGTH 16

#define DTLS_CLIENT_PEM_PATH "certs/client-cert.pem"
#define DTLS_CLIENT_KEY_PATH "certs/client-key.pem"
#define DTLS_CLIENT_DEFAULT_TIMEOUT 5

#define DTLS_SERVER_PEM_PATH "certs/server-cert.pem"
#define DTLS_SERVER_KEY_PATH "certs/server-key.pem"
#define DTLS_SERVER_DEFAULT_TIMEOUT 5

#define DTLS_CONNECTION_DEFAULT_TIMEOUT 5

////////////////////////////////////////////////////////////////////////////////

typedef union
{
    struct sockaddr_storage ss;
    struct sockaddr_in      s4;
    struct sockaddr_in6     s6;

} myaddr;

typedef struct dtlsClient
{
    int fd;

    SSL_CTX* ctx;
    SSL*     ssl;
    BIO*     bio;

    myaddr server_addr;
    struct timeval timeout;

} dtlsClient;

typedef void (*serverRecvFunc)(void* conn_info);

typedef struct dtlsServer
{
    int      fd;
    SSL_CTX* ctx;
    myaddr   local_addr;

    int       is_running;
    pthread_t listen_thread;

    serverRecvFunc callback;

    void* conn_arg;
    int   conn_arg_len;

} dtlsServer;

typedef struct dtlsConnInfo
{
    SSL *ssl;
    BIO *bio;

    myaddr client_addr;
    myaddr local_addr;

    struct timeval timeout;

    serverRecvFunc callback;

    void* conn_arg;

} dtlsConnInfo;

////////////////////////////////////////////////////////////////////////////////

static inline dtls_isAlive(SSL* ssl)
{
    return !(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN
             || SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN);
    // return !(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN);
}

int dtls_checkSslWrite(SSL* ssl, char* data, int len);
int dtls_checkSslRead(SSL* ssl, char* data, int len);

dtlsConnInfo* dtls_createConnInfo(BIO* bio, SSL* ssl, myaddr client_addr,
                                  dtlsServer *server);
void dtls_destroyConnInfo(dtlsConnInfo* info);

unsigned long dtls_idCallback(void);

int  dtls_initServer(const char* local_ip, const int local_port,
                     serverRecvFunc callback, void* conn_arg,
                     int conn_arg_len, dtlsServer* server);
int  dtls_uninitServer(dtlsServer* server);

int dtls_startServer(dtlsServer* server);
int dtls_stopServer(dtlsServer* server);

int  dtls_initClient(const char* remote_ip, int remote_port,
                     dtlsClient* client);
int  dtls_uninitClient(dtlsClient* client);

int  dtls_initSystem(void);
void dtls_uninitSystem(void);

#endif //_DTLS_API_H_
