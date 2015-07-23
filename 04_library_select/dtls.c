#include <stdio.h>
#include "dtls.h"

#define DTLS_END 0xABCD
#define DTLS_CONN_TIMEOUT 1
#define DTLS_BUF_SIZE 65535
#define DTLS_COOKIE_SECRET_LEN 16

#define derror(a, b...) fprintf(stderr, "[ERROR] %s(): "a"\n", __func__, ##b)
#define CHECK_IF(assertion, error_action, ...) \
{\
    if (assertion) \
    { \
        derror(__VA_ARGS__); \
        {error_action;} \
    }\
}

static unsigned char    _cookie_secret[DTLS_COOKIE_SECRET_LEN] = {0};
static int              _cookie_initialized                    = 0;

static void _showSocketError(void)
{
    switch (errno)
    {
        case EINTR:
            /* Interrupted system call.
             * Just ignore.
             */
            derror("Interrupted system call!");
            break;

        case EBADF:
            /* Invalid socket.
             * Must close connection.
             */
            derror("Invalid socket!");
            break;
#ifdef EHOSTDOWN
        case EHOSTDOWN:
            /* Host is down.
             * Just ignore, might be an attacker
             * sending fake ICMP messages.
             */
            derror("Host is down!");
            break;
#endif
#ifdef ECONNRESET
        case ECONNRESET:
            /* Connection reset by peer.
             * Just ignore, might be an attacker
             * sending fake ICMP messages.
             */
            derror("Connection reset by peer!");
            break;
#endif
        case ENOMEM:
            /* Out of memory.
             * Must close connection.
             */
            derror("Out of memory!");
            break;
        case EACCES:
            /* Permission denied.
             * Just ignore, we might be blocked
             * by some firewall policy. Try again
             * and hope for the best.
             */
            derror("Permission denied!");
            break;
        default:
            /* Something unexpected happened */
            derror("Unexpected error! (errno = %d)", errno);
            break;
    }

    return;
}

static int _verifyDtlsCallback(int ok, X509_STORE_CTX *ctx)
{
    /* This function should ask the user
     * if he trusts the received certificate.
     * Here we always trust.
     */
    return 1;
}

static unsigned long _dtlsIdCallback(void)
{
    return (unsigned long)pthread_self();
}

static int _checkSslWrite(SSL* ssl, char* buffer, int len)
{
    int ret = DTLS_FAIL;

    switch (SSL_get_error(ssl, len))
    {
        case SSL_ERROR_NONE:
            // dprint("wrote %d bytes", len);
            ret = DTLS_OK;
            break;

        case SSL_ERROR_WANT_WRITE:
            /* Just try again later */
            derror("SSL_ERROR_WANT_WRITE");
            break;

        case SSL_ERROR_WANT_READ:
            /* continue with reading */
            derror("SSL_ERROR_WANT_READ");
            break;

        case SSL_ERROR_SYSCALL:
            derror("Socket write error: ");
            _showSocketError();
            break;

        case SSL_ERROR_SSL:
            derror("SSL write error: ");
            derror("%s (%d)", ERR_error_string(ERR_get_error(), buffer),
                   SSL_get_error(ssl, len));
            break;

        default:
            derror("Unexpected error while writing!");
            break;
    }

    return ret;
}

static int _checkSslRead(SSL* ssl, char* buffer, int len)
{
    int ret = DTLS_FAIL;

    switch (SSL_get_error(ssl, len))
    {
        case SSL_ERROR_NONE:
            // dprint("read %d bytes", (int) len);
            ret = DTLS_OK;
            break;

        case SSL_ERROR_ZERO_RETURN:
            // dprint("no data to read");
            ret = DTLS_END;
            break;

        case SSL_ERROR_WANT_READ:
            /* Stop reading on socket timeout, otherwise try again */
            if (BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP,
                        0, NULL))
            {
                derror("Timeout! No response received.");
            }
            break;

        case SSL_ERROR_SYSCALL:
            derror("Socket read error: ");
            _showSocketError();
            break;

        case SSL_ERROR_SSL:
            derror("SSL read error: ");
            derror("%s (%d)", ERR_error_string(ERR_get_error(), buffer),
                   SSL_get_error(ssl, len));
            break;

        default:
            derror("Unexpected error while reading!\n");
            break;
    }

    return ret;
}

static int _isDtlsAlive(SSL* ssl)
{
    return !(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN
             || SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN);
    // return !(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN);
}

static int _generateCookie(SSL *ssl, unsigned char *cookie,
                           unsigned int *cookie_len)
{
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    union
    {
        struct sockaddr_storage ss;
        struct sockaddr_in      s4;
        struct sockaddr_in6     s6;
    } peer = {};

    /* Initialize a random secret */
    if (!_cookie_initialized)
    {
        if (!RAND_bytes(_cookie_secret, DTLS_COOKIE_SECRET_LEN))
        {
            derror("error setting random cookie secret");
            return 0;
        }
        _cookie_initialized = 1;
    }

    /* Read peer information */
    (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer's address and port */
    length = 0;
    switch (peer.ss.ss_family)
    {
        case AF_INET:
            length += sizeof(struct in_addr);
            break;

        case AF_INET6:
            length += sizeof(struct in6_addr);
            break;

        default:
            OPENSSL_assert(0);
            break;
    }

    length += sizeof(in_port_t);
    buffer = (unsigned char*) OPENSSL_malloc(length);

    if (buffer == NULL)
    {
        derror("out of memory\n");
        return 0;
    }

    switch (peer.ss.ss_family)
    {
        case AF_INET:
            memcpy(buffer,
                   &peer.s4.sin_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(peer.s4.sin_port),
                   &peer.s4.sin_addr,
                   sizeof(struct in_addr));
            break;

        case AF_INET6:
            memcpy(buffer,
                   &peer.s6.sin6_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(in_port_t),
                   &peer.s6.sin6_addr,
                   sizeof(struct in6_addr));
            break;

        default:
            OPENSSL_assert(0);
            break;
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), (const void*) _cookie_secret, DTLS_COOKIE_SECRET_LEN,
         (const unsigned char*) buffer, length, result, &resultlength);

    OPENSSL_free(buffer);

    memcpy(cookie, result, resultlength);
    *cookie_len = resultlength;

    return 1;
}

static int _verifyCookie(SSL *ssl, unsigned char *cookie,
                         unsigned int cookie_len)
{
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    union
    {
        struct sockaddr_storage ss;
        struct sockaddr_in      s4;
        struct sockaddr_in6     s6;
    } peer = {};

    /* If secret isn't initialized yet, the cookie can't be valid */
    if (!_cookie_initialized)
    {
        return 0;
    }

    /* Read peer information */
    (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer's address and port */
    length = 0;
    switch (peer.ss.ss_family)
    {
        case AF_INET:
            length += sizeof(struct in_addr);
            break;
        case AF_INET6:
            length += sizeof(struct in6_addr);
            break;
        default:
            OPENSSL_assert(0);
            break;
    }

    length += sizeof(in_port_t);
    buffer = (unsigned char*) OPENSSL_malloc(length);

    if (buffer == NULL)
    {
        derror("out of memory");
        return 0;
    }

    switch (peer.ss.ss_family)
    {
        case AF_INET:
            memcpy(buffer,
                   &peer.s4.sin_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(in_port_t),
                   &peer.s4.sin_addr,
                   sizeof(struct in_addr));
            break;

        case AF_INET6:
            memcpy(buffer,
                   &peer.s6.sin6_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(in_port_t),
                   &peer.s6.sin6_addr,
                   sizeof(struct in6_addr));
            break;

        default:
            OPENSSL_assert(0);
            break;
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), (const void*) _cookie_secret, DTLS_COOKIE_SECRET_LEN,
         (const unsigned char*) buffer, length, result, &resultlength);

    OPENSSL_free(buffer);

    if (cookie_len == resultlength
        && memcmp(result, cookie, resultlength) == 0)
    {
        return 1;
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

int dtls_to_sockaddr(struct dtls_addr dtls_addr, struct sockaddr_in* sock_addr)
{
    CHECK_IF(sock_addr == NULL, return DTLS_FAIL, "sock_addr is null");

    int chk = inet_pton(AF_INET, dtls_addr.ipv4, &sock_addr->sin_addr);
    CHECK_IF(chk != 1, return DTLS_FAIL, "inet_pton failed");

    sock_addr->sin_family = AF_INET;
    sock_addr->sin_port = htons(dtls_addr.port);
    return DTLS_OK;
}

int dtls_to_dtlsaddr(struct sockaddr_in sock_addr, struct dtls_addr* dtls_addr)
{
    CHECK_IF(dtls_addr == NULL, return DTLS_FAIL, "dtls_addr is null");

    inet_ntop(AF_INET, &sock_addr.sin_addr, dtls_addr->ipv4, INET_ADDRSTRLEN);
    dtls_addr->port = ntohs(sock_addr.sin_port);
    return DTLS_OK;
}

int dtls_server_init(struct dtls_server* server, char* local_ip, int local_port, char* cert_path, char* key_path, int timeout_sec)
{
    CHECK_IF(server == NULL, return DTLS_FAIL, "server is null");
    CHECK_IF(cert_path == NULL, return DTLS_FAIL, "cert_path is null");
    CHECK_IF(key_path == NULL, return DTLS_FAIL, "key_path is null");
    CHECK_IF(timeout_sec <= 0, return DTLS_FAIL, "timeout_sec <= 0");

    memset(server, 0, sizeof(struct dtls_server));

    snprintf(server->cert_path, DTLS_PATH_SIZE, "%s", cert_path);
    snprintf(server->key_path, DTLS_PATH_SIZE, "%s", key_path);

    int chk;
    struct sockaddr_in me = {};
    me.sin_family = AF_INET;
    if (local_ip)
    {
        chk = inet_pton(AF_INET, local_ip, &me.sin_addr);
        CHECK_IF(chk != 1, return DTLS_FAIL, "inet_pton failed");
    }
    else
    {
        me.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    me.sin_port = htons(local_port);

    int dtls_ret = dtls_to_dtlsaddr(me, &server->local);
    CHECK_IF(dtls_ret != DTLS_OK, return DTLS_FAIL, "dtls_to_dtlsaddr failed");

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    server->ctx = SSL_CTX_new(DTLSv1_server_method());

    // We accept all ciphers, including NULL.
    // Not recommended beyond testing and debugging

    SSL_CTX_set_cipher_list(server->ctx, "ALL:NULL:eNULL:aNULL");
    SSL_CTX_set_session_cache_mode(server->ctx, SSL_SESS_CACHE_OFF);

    if (!SSL_CTX_use_certificate_file(server->ctx, cert_path, SSL_FILETYPE_PEM))
    {
        derror("ERROR: no certificate found!");
        goto _ERROR;
    }

    if (!SSL_CTX_use_PrivateKey_file(server->ctx, key_path, SSL_FILETYPE_PEM))
    {
        derror("ERROR: no private key found!");
        goto _ERROR;
    }

    if (!SSL_CTX_check_private_key(server->ctx))
    {
        derror("ERROR: invalid private key!");
        goto _ERROR;
    }

    /* Client has to authenticate */
    SSL_CTX_set_verify(server->ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, _verifyDtlsCallback);
    SSL_CTX_set_read_ahead(server->ctx, 1);
    SSL_CTX_set_cookie_generate_cb(server->ctx, _generateCookie);
    SSL_CTX_set_cookie_verify_cb(server->ctx, _verifyCookie);

    const int on = 1, off = 0;
    server->fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK_IF(server->fd < 0, goto _ERROR, "socket create failed");

    chk = setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, (const void*)&on, (socklen_t)sizeof(on));
    CHECK_IF(chk < 0, goto _ERROR, "setsockopt reuse addr failed");

    chk = bind(server->fd, (const struct sockaddr*)&me, sizeof(struct sockaddr_in));
    CHECK_IF(chk < 0, goto _ERROR, "bind AF_INET failed");

    server->is_init = 1;
    return DTLS_OK;

_ERROR:
    dtls_server_uninit(server);
    return DTLS_FAIL;
}

int dtls_server_uninit(struct dtls_server* server)
{
    CHECK_IF(server == NULL, return DTLS_FAIL, "server is null");

    if (server->fd > 0)
    {
        close(server->fd);
        server->fd = -1;
    }

    if (server->ctx)
    {
        SSL_CTX_free(server->ctx);
        server->ctx = NULL;
    }

    ERR_free_strings();
    EVP_cleanup();
    ERR_remove_state(0);

    server->is_init = 0;
    return DTLS_OK;
}

int dtls_server_accept(struct dtls_server* server, struct dtls* dtls)
{
    CHECK_IF(server == NULL, return DTLS_FAIL, "server is null");
    CHECK_IF(dtls == NULL, return DTLS_FAIL, "dtls is null");
    CHECK_IF(server->is_init != 1, return DTLS_FAIL, "server is not init yet");

    memset(dtls, 0, sizeof(struct dtls));

    union {
        struct sockaddr_storage ss;
        struct sockaddr_in      s4;
        struct sockaddr_in6     s6;
    } remote;

    /* Create BIO */
    dtls->bio = BIO_new_dgram(server->fd, BIO_NOCLOSE);
    CHECK_IF(dtls->bio == NULL, goto _ERROR, "BIO_new_dgram failed");

    /* Set and activate timeouts */
    struct timeval timeout = {};
    timeout.tv_sec  = DTLS_CONN_TIMEOUT;
    timeout.tv_usec = 0;

    BIO_ctrl(dtls->bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    dtls->ssl = SSL_new(server->ctx);
    CHECK_IF(dtls->ssl == NULL, goto _ERROR, "SSL_new failed");

    SSL_set_bio(dtls->ssl, dtls->bio, dtls->bio);
    SSL_set_options(dtls->ssl, SSL_OP_COOKIE_EXCHANGE);

    server->accept_run = 1;

    while (DTLSv1_listen(dtls->ssl, &remote) <= 0)
    {
        if (server->accept_run != 1) goto _ERROR;
    }

    int dtls_ret = dtls_to_dtlsaddr(remote.s4, &dtls->remote);
    CHECK_IF(dtls_ret != DTLS_OK, goto _ERROR, "dtls_to_dtlsaddr failed");

    struct sockaddr_in me = {};
    dtls_ret = dtls_to_sockaddr(server->local, &me);
    CHECK_IF(dtls_ret != DTLS_OK, goto _ERROR, "dtls_to_sockaddr failed");

    dtls->fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK_IF(dtls->fd < 0, goto _ERROR, "socket failed");

    const int on = 1, off = 0;
    int chk = setsockopt(dtls->fd, SOL_SOCKET, SO_REUSEADDR, (const void*)&on, (socklen_t)sizeof(on));
    CHECK_IF(chk < 0, goto _ERROR, "setsockopt reuse addr failed");

    chk = bind(dtls->fd, (const struct sockaddr*)&me, sizeof(struct sockaddr_in));
    CHECK_IF(chk < 0, goto _ERROR, "bind failed");

    chk = connect(dtls->fd, (struct sockaddr*)&remote.s4, sizeof(struct sockaddr_in));
    CHECK_IF(chk < 0, goto _ERROR, "connect failed");

    struct sockaddr_storage ss = {.ss_family = AF_INET};

    /* Set new fd and set BIO to connected */
    BIO_set_fd(SSL_get_rbio(dtls->ssl), dtls->fd, BIO_NOCLOSE);
    BIO_ctrl(SSL_get_rbio(dtls->ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &ss);

    /* Finish handshake */
    do
    {
        chk = SSL_accept(dtls->ssl);

    } while (chk == 0);

    if (chk < 0)
    {
        char buffer[DTLS_BUF_SIZE];
        derror("SSL_accept");
        derror("%s", ERR_error_string(ERR_get_error(), buffer));
        goto _ERROR;
    }

    timeout.tv_sec = server->timeout_sec;
    timeout.tv_usec = 0;

    BIO_ctrl(SSL_get_rbio(dtls->ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    X509* pX509 = SSL_get_peer_certificate(dtls->ssl);
    if (pX509)
    {
        printf("\n");
        X509_NAME_print_ex_fp(stdout, X509_get_subject_name(pX509),
                              1, XN_FLAG_MULTILINE);
        printf("\n\n");
        // printf("Cipher: %s",
        //        SSL_CIPHER_get_name(SSL_get_current_cipher(info->ssl)));
        // printf("-----------------------------------------------------------\n");

        X509_free(pX509);
    }

    dtls->is_init = 1;
    return DTLS_OK;

_ERROR:
    dtls_client_uninit(dtls);
    return DTLS_FAIL;
}

int dtls_client_init(struct dtls* dtls, char* remote_ip, int remote_port, int local_port, char* cert_path, char* key_path, int timeout_sec)
{
    CHECK_IF(dtls == NULL, return DTLS_FAIL, "dtls is null");
    CHECK_IF(remote_ip == NULL, return DTLS_FAIL, "remote_ip is null");
    CHECK_IF(cert_path == NULL, return DTLS_FAIL, "cert_path is null");
    CHECK_IF(key_path == NULL, return DTLS_FAIL, "key_path is null");
    CHECK_IF(timeout_sec <= 0, return DTLS_FAIL, "timeout_sec = %d invalid", timeout_sec);

    memset(dtls, 0, sizeof(struct dtls));

    snprintf(dtls->cert_path, DTLS_PATH_SIZE, "%s", cert_path);
    snprintf(dtls->key_path, DTLS_PATH_SIZE, "%s", key_path);

    struct timeval timeout = {};
    timeout.tv_sec  = timeout_sec;
    timeout.tv_usec = 0;

    dtls->fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK_IF(dtls->fd < 0, return DTLS_FAIL, "socket failed");

    struct sockaddr_in me = {};
    me.sin_family = AF_INET;
    if (local_port != DTLS_PORT_ANY)
    {
        me.sin_port = htons(local_port);
    }

    struct sockaddr_in remote = {};
    remote.sin_family = AF_INET;
    int chk = inet_pton(AF_INET, remote_ip, &remote.sin_addr);
    CHECK_IF(chk != 1, goto _ERROR, "inet_pton failed");
    remote.sin_port = htons(remote_port);

    int dtls_ret = dtls_to_dtlsaddr(remote, &dtls->remote);
    CHECK_IF(dtls_ret != DTLS_OK, goto _ERROR, "dtls_to_dtlsaddr failed");

    const int on = 1;
    chk = setsockopt(dtls->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    CHECK_IF(chk < 0, goto _ERROR, "setsockopt reuse addr failed");

    chk = bind(dtls->fd, (struct sockaddr*)&me, sizeof(struct sockaddr_in));
    CHECK_IF(chk < 0, goto _ERROR, "bind failed");

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    dtls->ctx = SSL_CTX_new(DTLSv1_client_method());
    SSL_CTX_set_cipher_list(dtls->ctx, "eNULL:!MD5");

    if (!SSL_CTX_use_certificate_file(dtls->ctx, dtls->cert_path, SSL_FILETYPE_PEM))
    {
        derror("ERROR: no certificate found!");
        goto _ERROR;
    }

    if (!SSL_CTX_use_PrivateKey_file(dtls->ctx, dtls->key_path, SSL_FILETYPE_PEM))
    {
        derror("ERROR: no private key found!");
        goto _ERROR;
    }

    if (!SSL_CTX_check_private_key(dtls->ctx))
    {
        derror("ERROR: invalid private key!");
        goto _ERROR;
    }

    SSL_CTX_set_verify_depth(dtls->ctx, 2);
    SSL_CTX_set_read_ahead(dtls->ctx, 1);

    dtls->ssl = SSL_new(dtls->ctx);

    /* Create BIO, connect and set to already connected */
    dtls->bio = BIO_new_dgram(dtls->fd, BIO_CLOSE);

    chk = connect(dtls->fd, (struct sockaddr*)&remote, sizeof(struct sockaddr_in));
    CHECK_IF(chk < 0, goto _ERROR, "connect failed");

    struct sockaddr_storage ss = {.ss_family = AF_INET};

    BIO_ctrl(dtls->bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &ss);

    SSL_set_bio(dtls->ssl, dtls->bio, dtls->bio);

    chk = SSL_connect(dtls->ssl);
    CHECK_IF(chk < 0, goto _ERROR, "SSL_connect failed");

    BIO_ctrl(dtls->bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    //////////////////////////////////////////////////////////////////
    // SSL_get_peer_certificate will allocate a new memory for X509
    // do remember to free it
    //////////////////////////////////////////////////////////////////
    X509* pX509 = SSL_get_peer_certificate(dtls->ssl);
    if (pX509)
    {
        printf("\n");
        X509_NAME_print_ex_fp(stdout, X509_get_subject_name(pX509),
                              1, XN_FLAG_MULTILINE);
        printf("\n\n");

        X509_free(pX509);
    }

    dtls->is_init = 1;

    return DTLS_OK;

_ERROR:
    dtls_client_uninit(dtls);
    return DTLS_FAIL;
}

int dtls_client_uninit(struct dtls* dtls)
{
    CHECK_IF(dtls == NULL, return DTLS_FAIL, "dtls is null");
    // CHECK_IF(dtls->is_init != 1, return DTLS_FAIL, "dtls is not init yet");

    if (dtls->ssl)
    {
        SSL_shutdown(dtls->ssl);
        SSL_free(dtls->ssl);
        dtls->ssl = NULL;
    }

    if (dtls->fd > 0)
    {
        close(dtls->fd);
        dtls->fd = -1;
    }

    if (dtls->ctx)
    {
        SSL_CTX_free(dtls->ctx);
        dtls->ctx = NULL;
    }

    ERR_remove_state(0);
    ERR_free_strings();
    EVP_cleanup();

    dtls->is_init = 0;
    return DTLS_OK;
}

int dtls_recv(struct dtls* dtls, void* buffer, int buffer_size)
{
    CHECK_IF(dtls == NULL, return -1, "dtls is null");
    CHECK_IF(buffer == NULL, return -1, "buffer is null");
    CHECK_IF(buffer_size <= 0, return -1, "buffer_size <= 0");
    CHECK_IF(dtls->is_init != 1, return -1, "dtls is not init yet");
    CHECK_IF(!_isDtlsAlive(dtls->ssl), return -1, "dtls ssl is not alive");

    int readlen = SSL_read(dtls->ssl, buffer, buffer_size);
    int chk = _checkSslRead(dtls->ssl, buffer, readlen);
    CHECK_IF(chk != DTLS_OK, return -1, "_checkSslRead failed");
    return readlen;
}

int dtls_send(struct dtls* dtls, void* data, int data_len)
{
    CHECK_IF(dtls == NULL, return -1, "dtls is null");
    CHECK_IF(data == NULL, return -1, "data is null");
    CHECK_IF(data_len <= 0, return -1, "data_len <= 0");
    CHECK_IF(dtls->is_init != 1, return -1, "dtls is not init yet");
    CHECK_IF(!_isDtlsAlive(dtls->ssl), return -1, "dtls ssl is not alive");

    int writelen = SSL_write(dtls->ssl, data, data_len);
    int chk = _checkSslWrite(dtls->ssl, data, writelen);
    CHECK_IF(chk != DTLS_OK, return -1, "_checkSslWrite failed");
    return writelen;
}
