
#include "basic.h"
#include "dtls.h"

////////////////////////////////////////////////////////////////////////////////

static unsigned char    _cookie_secret[COOKIE_SECRET_LENGTH] = {0};
static int              _cookie_initialized = 0;
static pthread_mutex_t* _mutex_buf       = NULL;

////////////////////////////////////////////////////////////////////////////////

static int _createUnixSocketServer(dtlsServer* server)
{
    int  check    = -1;
    int  fd       = -1;
    struct sockaddr_un local = {.sun_family = AF_UNIX};

    check_if(server == NULL, goto _ERROR, "server is null");

    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    check_if(fd < 0, goto _ERROR, "socket failed");

    strncpy(local.sun_path, server->unpath, sizeof(local.sun_path) - 1);

    check = bind(fd, (struct sockaddr*)&local, sizeof(struct sockaddr_un));
    check_if(check < 0, goto _ERROR, "bind failed");

    server->fd             = fd;
    server->un_server_addr = local;

    return DTLS_OK;

_ERROR:
    if (fd > 0)
    {
        close(fd);
    }

    server->fd = -1;
    return DTLS_FAIL;
}

static int _createUnixSocketClient(dtlsServer* server)
{
    int fd = -1;
    struct sockaddr_un unaddr = {.sun_family = AF_UNIX};

    check_if(server == NULL, goto _ERROR, "server is null");

    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    check_if(fd < 0, goto _ERROR, "socket failed");

    strncpy(unaddr.sun_path, server->unpath, sizeof(unaddr.sun_path) - 1);
    
    server->un_client_fd   = fd;
    server->un_client_addr = unaddr;

    return DTLS_OK;

_ERROR:
    if (fd > 0)
    {
        close(fd);
    }
    server->un_client_fd = -1;
    return DTLS_FAIL;
}

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

static int _saveConnInfo(dtlsServer* server, dtlsConnInfo* info)
{
    check_if(server == NULL, return DTLS_FAIL, "server is null");
    check_if(info == NULL, return DTLS_FAIL, "info is null");

    info->next         = server->conn_list;
    server->conn_list = info;

    return DTLS_OK;
}

static void _destroyConnInfo(dtlsConnInfo* info)
{
    dtlsServer* server = NULL;
    dtlsConnInfo* curr = NULL;
    dtlsConnInfo* prev = NULL;

    check_if(info == NULL, return, "info is null");

    server = (dtlsServer*)info->server;

    curr = server->conn_list;
    while (curr)
    {
        if (curr == info)
        {
            if (prev)
            {
                prev->next = curr->next;
            }
            else
            {
                server->conn_list = NULL;
            }

            curr->next = NULL;
            dprint("dtlsConnInfo found, remove from list");
            break;
        }
        prev = curr;
        curr = curr->next;
    }

    if (info->ssl)
    {
        SSL_free(info->ssl);
        info->ssl = NULL;
    }

    free(info);

    dprint("over");
    return;
}

static dtlsConnInfo* _createConnInfo(BIO* bio, SSL* ssl, myaddr client_addr,
                                     dtlsServer *server)
{
    dtlsConnInfo* info = NULL;
    int check;

    check_if(bio == NULL, return NULL, "bio is null");
    check_if(ssl == NULL, return NULL, "ssl is null");
    check_if(server == NULL, return NULL, "server is null");

    info      = (dtlsConnInfo*)calloc(sizeof(dtlsConnInfo), 1);
    info->bio = bio;
    info->ssl = ssl;

    memcpy(&info->client_addr, &client_addr, sizeof(struct sockaddr_storage));
    memcpy(&info->local_addr,  &server->local_addr,
           sizeof(struct sockaddr_storage));

    info->timeout.tv_sec  = DTLS_SERVER_DEFAULT_TIMEOUT;
    info->timeout.tv_usec = 0;

    info->server = server;

    check = _saveConnInfo(server, info);
    check_if(check != DTLS_OK, goto _ERROR, "_saveConnInfo failed");

    return info;

_ERROR:
    _destroyConnInfo(info);
    return NULL;
}

static int _isDtlsAlive(SSL* ssl)
{
    return !(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN
             || SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN);
    // return !(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN);
}

static unsigned long _dtlsIdCallback(void)
{
    return (unsigned long)pthread_self();
}

static void _sslLockFunc(int mode, int n, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
    {
        pthread_mutex_lock(&_mutex_buf[n]);
    }
    else
    {
        pthread_mutex_unlock(&_mutex_buf[n]);
    }
}

static int _configAddr(const char* ip_str, const int port, myaddr* addr)
{
    check_if(ip_str == NULL, return DTLS_FAIL, "ip_str is null");
    check_if(addr == NULL, return DTLS_FAIL, "addr is null");

    if (inet_pton(AF_INET, ip_str, &(addr->s4.sin_addr)) == 1)
    {
        addr->s4.sin_family = AF_INET;

        #ifdef HAVE_SIN_LEN
            addr->s4.sin_len = sizeof(struct sockaddr_in);
        #endif

        addr->s4.sin_port = htons(port);
    }
    else if (inet_pton(AF_INET6, ip_str, &(addr->s6.sin6_addr)) == 1)
    {
        addr->s6.sin6_family = AF_INET6;

        #ifdef HAVE_SIN6_LEN
            addr->s6.sin6_len = sizeof(struct sockaddr_in6);
        #endif

        addr->s6.sin6_port = htons(port);
    }
    else
    {
        return DTLS_FAIL;
    }

    return DTLS_OK;
}

static int _verifyCookie(SSL *ssl, unsigned char *cookie,
                         unsigned int cookie_len)
{
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    myaddr peer = {};

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
    HMAC(EVP_sha1(), (const void*) _cookie_secret, COOKIE_SECRET_LENGTH,
         (const unsigned char*) buffer, length, result, &resultlength);

    OPENSSL_free(buffer);

    if (cookie_len == resultlength
        && memcmp(result, cookie, resultlength) == 0)
    {
        return 1;
    }

    return 0;

}

static int _generateCookie(SSL *ssl, unsigned char *cookie,
                           unsigned int *cookie_len)
{
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    myaddr peer= {};

    /* Initialize a random secret */
    if (!_cookie_initialized)
    {
        if (!RAND_bytes(_cookie_secret, COOKIE_SECRET_LENGTH))
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
    HMAC(EVP_sha1(), (const void*) _cookie_secret, COOKIE_SECRET_LENGTH,
         (const unsigned char*) buffer, length, result, &resultlength);

    OPENSSL_free(buffer);

    memcpy(cookie, result, resultlength);
    *cookie_len = resultlength;

    return 1;

}

static int _verifyDtlsCallback(int ok, X509_STORE_CTX *ctx)
{
    /* This function should ask the user
     * if he trusts the received certificate.
     * Here we always trust.
     */
    return 1;
}

int _acceptSslConn(dtlsConnInfo *info, int fd, char* buffer, char* addr_buf)
{
    int check;

    check_if(info     == NULL, return DTLS_FAIL, "info is null");
    check_if(buffer   == NULL, return DTLS_FAIL, "buffer is null");
    check_if(addr_buf == NULL, return DTLS_FAIL, "addr_buf is null");

    /* Set new fd and set BIO to connected */
    BIO_set_fd(SSL_get_rbio(info->ssl), fd, BIO_NOCLOSE);
    BIO_ctrl(SSL_get_rbio(info->ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0,
             &info->client_addr.ss);

    /* Finish handshake */
    do
    {
        check = SSL_accept(info->ssl);

    } while (check == 0);

    if (check < 0)
    {
        derror("SSL_accept");
        derror("%s", ERR_error_string(ERR_get_error(), buffer));
        return DTLS_FAIL;
    }

    BIO_ctrl(SSL_get_rbio(info->ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0,
             &info->timeout);

    X509* pX509 = SSL_get_peer_certificate(info->ssl);
    if (pX509)
    {
        printf("\n");
        X509_NAME_print_ex_fp(stdout, X509_get_subject_name(pX509),
                              1, XN_FLAG_MULTILINE);
        printf("\n\n");
        printf("Cipher: %s",
               SSL_CIPHER_get_name(SSL_get_current_cipher(info->ssl)));
        printf("-----------------------------------------------------------\n");

        X509_free(pX509);
    }

    return DTLS_OK;

}

static void _transferDataToUnixSocketServer(dtlsConnInfo* info)
{
    int  i;
    char buffer[BUFFER_SIZE] = {0};
    int  readlen;
    int  sendlen;
    int  check;
    SSL* ssl;
    dtlsServer* server;

    check_if(info == NULL, goto _END, "info is null");

    ssl = info->ssl;
    check_if(ssl == NULL, goto _END, "ssl is null");

    server = (dtlsServer*)info->server;
    check_if(server == NULL, goto _END, "info->server is null");

    while (_isDtlsAlive(ssl) && server->is_started)
    {
        readlen = SSL_read(ssl, buffer, BUFFER_SIZE);
        check = _checkSslRead(ssl, buffer, readlen);
        if (check == DTLS_FAIL)
        {
            derror("_checkSslRead failed");
            goto _END;
        }
        else if (check == DTLS_END)
        {
            dprint("dtls end");
            goto _END;
        }

        dprint("read : %s", buffer);

        sendlen = sendto(server->un_client_fd, buffer, readlen, 0, 
                         (struct sockaddr*)&server->un_client_addr,
                         sizeof(struct sockaddr_un));
        if (sendlen <= 0)
        {
            derror("send to unix socket failed");
            goto _END;
        }
    }

_END:
    return;
}


static void* _handleDtlsConn(void *arg)
{
    dtlsConnInfo *info = (dtlsConnInfo*)arg;

    int check;

    pthread_detach(pthread_self());
    OPENSSL_assert(info->client_addr.ss.ss_family == info->local_addr.ss.ss_family);

    ///////////////////////////////////////////////////////////////////////////
    // Open new Socket, bind, connect
    ///////////////////////////////////////////////////////////////////////////
    int fd;
    const int on = 1, off = 0;

    fd = socket(info->client_addr.ss.ss_family, SOCK_DGRAM, 0);
    check_if(fd < 0, goto _CLEANUP, "socket failed");

    check = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*)&on,
                       (socklen_t)sizeof(on));
    check_if(check < 0, goto _CLEANUP, "setsockopt reuse addr failed");

    switch (info->client_addr.ss.ss_family)
    {
        case AF_INET:
            check = bind(fd, (const struct sockaddr*)&info->local_addr,
                         sizeof(struct sockaddr_in));
            check_if(check < 0, goto _CLEANUP,
                     "AF_INET bind local addr failed");

            check = connect(fd, (struct sockaddr*)&info->client_addr,
                            sizeof(struct sockaddr_in));
            check_if(check < 0, goto _CLEANUP,
                     "AF_INET connect client addr failed");

            break;

        case AF_INET6:
            check = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off,
                               sizeof(off));
            check_if(check < 0, goto _CLEANUP,
                     "AF_INET6 setsockopt IPV6_V6ONLY failed");

            check = bind(fd, (const struct sockaddr*)&info->local_addr,
                         sizeof(struct sockaddr_in6));
            check_if(check < 0, goto _CLEANUP,
                     "AF_INET6 bind local addr failed");

            check = connect(fd, (struct sockaddr*) &info->client_addr,
                            sizeof(struct sockaddr_in6));
            check_if(check < 0, goto _CLEANUP,
                     "AF_INET6 connect client addr failed");

            break;

        default:
            goto _CLEANUP;
            // break;
    }

    ///////////////////////////////////////////////////////////////////////////
    // New Socket Accept
    ///////////////////////////////////////////////////////////////////////////
    char buf[BUFFER_SIZE];
    char addrbuf[INET6_ADDRSTRLEN];

    check = _acceptSslConn(info, fd, buf, addrbuf);
    check_if(check != DTLS_OK, goto _CLEANUP, "_acceptSslConn failed");

    ///////////////////////////////////////////////////////////////////////////
    // New Socket Reception
    ///////////////////////////////////////////////////////////////////////////
    _transferDataToUnixSocketServer(info);

_CLEANUP:
    SSL_shutdown(info->ssl);
    dprint("shutdown SSL");

    _destroyConnInfo(info);
    dprint("Thread %lx: done, connection closed.", _dtlsIdCallback());

    ERR_remove_state(0);
    pthread_exit(0);
}

static void* _listenDtlsServer(void* arg)
{
    dtlsServer*    server      = (dtlsServer*)arg;
    myaddr         client_addr = {};
    BIO*           bio         = NULL;
    SSL*           ssl         = NULL;
    struct timeval timeout     = {};
    dtlsConnInfo*  info        = NULL;
    int            check;
    pthread_t      conn_thread;

    check_if(arg == NULL, goto _END, "arg is null");

    while (server->is_started)
    {
        info = NULL;

        memset(&client_addr, 0, sizeof(struct sockaddr_storage));

        /* Create BIO */
        bio = BIO_new_dgram(server->dtls_fd, BIO_NOCLOSE);
        check_if(bio == NULL, goto _END, "BIO_new_dgram failed");

        /* Set and activate timeouts */
        timeout.tv_sec  = DTLS_CONNECTION_DEFAULT_TIMEOUT;
        timeout.tv_usec = 0;

        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        ssl = SSL_new(server->ctx);
        check_if(ssl == NULL, goto _END, "SSL_new failed");

        SSL_set_bio(ssl, bio, bio);
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

        while (DTLSv1_listen(ssl, &client_addr) <= 0)
        {
            if (server->is_started == FALSE)
            {
                dprint("here");
                goto _END;
            }
        }

        info = _createConnInfo(bio, ssl, client_addr, server);
        check_if(info == NULL, goto _END, "_createConnInfo failed");

        check = pthread_create(&conn_thread, NULL, _handleDtlsConn, info);
        check_if(check != 0, goto _END, "pthread_create failed");

        ssl = NULL;
        bio = NULL;
    }

_END:
    if (server->dtls_fd > 0)
    {
        close(server->dtls_fd);
        server->dtls_fd = -1;
    }

    if (info)
    {
        _destroyConnInfo(info);
    }

    if (ssl)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = NULL;
    }

    dprint("Thread %lx: done, connection closed.", _dtlsIdCallback());

    ERR_remove_state(0);
    pthread_exit(0);
}

////////////////////////////////////////////////////////////////////////////////

int dtls_startServer(dtlsServer* server)
{
    check_if(server == NULL, return DTLS_FAIL, "server is null");
    check_if(server->is_started == TRUE, return DTLS_FAIL, "server is started");

    server->is_started = TRUE;
    pthread_create(&server->listen_thread, NULL, _listenDtlsServer, server);

    dprint("ok");
    return DTLS_OK;
}

int dtls_stopServer(dtlsServer* server)
{
    check_if(server == NULL, return DTLS_FAIL, "server is null");
    check_if(server->is_started == FALSE, return DTLS_FAIL,"server is stopped");

    dprint("wait listen thread over...");

    server->is_started = FALSE;
    pthread_join(server->listen_thread, NULL);

    int i;
    for (i=0; i<DTLS_SERVER_DEFAULT_TIMEOUT && server->conn_list; i++)
    {
        dprint("wait for all conn thread over ... %d secs", (i+1));
        sleep(1);
    }

    dprint("ok");

    return DTLS_OK;
}

int dtls_initServer(const char* local_ip, const int local_port,
                    dtlsServer* server)
{
    int check;

    check_if(server == NULL, return DTLS_FAIL, "server is null");

    memset(server, 0, sizeof(dtlsServer));

    if (local_ip)
    {
        check = _configAddr(local_ip, local_port, &server->local_addr);
        check_if(check != DTLS_OK, goto _ERROR, "_configAddr failed");
    }
    else
    {
        server->local_addr.s6.sin6_family = AF_INET6;
        server->local_addr.s6.sin6_addr   = in6addr_any;
        server->local_addr.s6.sin6_port   = htons(local_port);
#ifdef HAVE_SIN6_LEN
        server->local_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
    }

    snprintf(server->unpath, 20, "DTLS_SERVER_%d", local_port);
    unlink(server->unpath);

    check = _createUnixSocketServer(server);
    check_if(check != DTLS_OK, goto _ERROR, "_createUnixSocketServer failed");

    check = _createUnixSocketClient(server);
    check_if(check != DTLS_OK, goto _ERROR, "_createUnixSocketClient failed");

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    server->ctx = SSL_CTX_new(DTLSv1_server_method());

    // We accept all ciphers, including NULL.
    // Not recommended beyond testing and debugging

    SSL_CTX_set_cipher_list(server->ctx, "ALL:NULL:eNULL:aNULL");
    SSL_CTX_set_session_cache_mode(server->ctx, SSL_SESS_CACHE_OFF);

    if (!SSL_CTX_use_certificate_file(server->ctx, DTLS_SERVER_PEM_PATH,
                                        SSL_FILETYPE_PEM))
    {
        derror("ERROR: no certificate found!");
        goto _ERROR;
    }

    if (!SSL_CTX_use_PrivateKey_file(server->ctx, DTLS_SERVER_KEY_PATH,
                                        SSL_FILETYPE_PEM))
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
    SSL_CTX_set_verify(server->ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
                       _verifyDtlsCallback);
    SSL_CTX_set_read_ahead(server->ctx, 1);
    SSL_CTX_set_cookie_generate_cb(server->ctx, _generateCookie);
    SSL_CTX_set_cookie_verify_cb(server->ctx, _verifyCookie);

    const int on = 1, off = 0;
    server->dtls_fd = socket(server->local_addr.ss.ss_family, SOCK_DGRAM, 0);
    check_if(server->dtls_fd < 0, goto _ERROR, "socket create failed");

    check = setsockopt(server->dtls_fd, SOL_SOCKET, SO_REUSEADDR, 
                       (const void*)&on, (socklen_t)sizeof(on));
    check_if(check < 0, goto _ERROR, "setsockopt reuse addr failed");

    if (server->local_addr.ss.ss_family == AF_INET)
    {
        check = bind(server->dtls_fd, 
                     (const struct sockaddr*)&server->local_addr,
                     sizeof(struct sockaddr_in));
        check_if(check < 0, goto _ERROR, "bind AF_INET failed");
    }
    else
    {
        check = setsockopt(server->dtls_fd, IPPROTO_IPV6, IPV6_V6ONLY, 
                           (char*)&off, sizeof(off));
        check_if(check < 0, goto _ERROR, "setsockopt ipv6 only failed");

        check = bind(server->dtls_fd, 
                     (const struct sockaddr*)&server->local_addr,
                     sizeof(struct sockaddr_in6));
        check_if(check < 0, goto _ERROR, "bind AF_INET6 failed");
    }

    server->is_started = FALSE;

    dprint("ok");

    return DTLS_OK;

_ERROR:
    dtls_uninitServer(server);
    return DTLS_FAIL;

 }

int dtls_uninitServer(dtlsServer* server)
{
    check_if(server == NULL, return DTLS_FAIL, "server is null");

    if (server->is_started)
    {
        dtls_stopServer(server);
    }

    unlink(server->unpath);

    if (server->fd > 0)
    {
        close(server->fd);
    }

    if (server->un_client_fd > 0)
    {
        close(server->un_client_fd);
    }

    if (server->dtls_fd > 0)
    {
        close(server->dtls_fd);
    }

    if (server->ctx)
    {
        SSL_CTX_free(server->ctx);
        server->ctx = NULL;
    }

    ERR_free_strings();
    EVP_cleanup();
    ERR_remove_state(0);

    dprint("ok");

    return DTLS_OK;
}

int dtls_recvData(dtlsServer* server, void* buffer, int buffer_size)
{
    check_if(server == NULL, return -1, "server is null");
    check_if(buffer == NULL, return -1, "buffer is null");
    check_if(buffer_size <= 0, return -1, "buffer_size is %d", buffer_size);
    check_if(server->is_started == FALSE, return -1, 
             "server is not started yet");

    int recvlen;
    int addrlen = sizeof(struct sockaddr_un);
    struct sockaddr_un unused;

    recvlen = recvfrom(server->fd, buffer, buffer_size, 0,
                       (struct sockaddr*)&unused, &addrlen);
    if (recvlen <= 0)
    {
        derror("recvfrom failed");
    }

    return recvlen;
}

int dtls_initClient(const char* remote_ip, int remote_port, dtlsClient* client)
{
    int check;

    check_if(client == NULL,    return DTLS_FAIL, "client is null");
    check_if(remote_ip == NULL, return DTLS_FAIL, "remote_ip is null");

    memset(client, 0, sizeof(dtlsClient));

    check = _configAddr(remote_ip, remote_port, &(client->server_addr));
    check_if(check != DTLS_OK, return check, "_configAddr failed");

    client->timeout.tv_sec  = DTLS_CLIENT_DEFAULT_TIMEOUT;
    client->timeout.tv_usec = 0;

    return DTLS_OK;
}

int dtls_uninitClient(dtlsClient* client)
{
    check_if(client == NULL, return DTLS_FAIL, "client is null");

    if (client->is_started)
    {
        dtls_stopClient(client);
    }

    if (client->fd > 0)
    {
        close(client->fd);
    }

    /////////////////////////////////////////////////////////
    // when you free ssl, bio will be free at the same time
    /////////////////////////////////////////////////////////
    if (client->ssl)
    {
        SSL_free(client->ssl);
        client->ssl = NULL;
    }

    if (client->ctx)
    {
        SSL_CTX_free(client->ctx);
        client->ctx = NULL;
    }

    //////////////////////////////////////
    // avoid some memory leakage problem
    //////////////////////////////////////
    ERR_remove_state(0);
    ERR_free_strings();
    EVP_cleanup();

    dprint("ok");

    return DTLS_OK;
}

int dtls_startClient(dtlsClient* client)
{
    check_if(client == NULL, return DTLS_FAIL, "client is null");
    check_if(client->is_started == TRUE, return DTLS_FAIL, "client is started");

    client->fd = socket(client->server_addr.ss.ss_family, SOCK_DGRAM, 0);
    check_if(client->fd < 0, return DTLS_FAIL, "socket failed");

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    client->ctx = SSL_CTX_new(DTLSv1_client_method());
    SSL_CTX_set_cipher_list(client->ctx, "eNULL:!MD5");

    if (!SSL_CTX_use_certificate_file(client->ctx, DTLS_CLIENT_PEM_PATH,
                                        SSL_FILETYPE_PEM))
    {
        derror("ERROR: no certificate found!");
        goto _ERROR;
    }

    if (!SSL_CTX_use_PrivateKey_file(client->ctx, DTLS_CLIENT_KEY_PATH,
                                        SSL_FILETYPE_PEM))
    {
        derror("ERROR: no private key found!");
        goto _ERROR;
    }

    if (!SSL_CTX_check_private_key(client->ctx))
    {
        derror("ERROR: invalid private key!");
        goto _ERROR;
    }

    SSL_CTX_set_verify_depth(client->ctx, 2);
    SSL_CTX_set_read_ahead(client->ctx, 1);

    client->ssl = SSL_new(client->ctx);

    /* Create BIO, connect and set to already connected */
    client->bio = BIO_new_dgram(client->fd, BIO_CLOSE);
    if (client->server_addr.ss.ss_family == AF_INET)
    {
        connect(client->fd, (struct sockaddr*)&client->server_addr,
                sizeof(struct sockaddr_in));
    }
    else
    {
        connect(client->fd, (struct sockaddr*)&client->server_addr,
                sizeof(struct sockaddr_in6));
    }

    BIO_ctrl(client->bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0,
             &(client->server_addr.ss));

    SSL_set_bio(client->ssl, client->bio, client->bio);

    if (SSL_connect(client->ssl) < 0)
    {
        derror("SSL_connect failed");
        goto _ERROR;
    }

    BIO_ctrl(client->bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0,
             &client->timeout);

    //////////////////////////////////////////////////////////////////
    // SSL_get_peer_certificate will allocate a new memory for X509
    // do remember to free it
    //////////////////////////////////////////////////////////////////
    X509* pX509 = SSL_get_peer_certificate(client->ssl);
    if (pX509)
    {
        printf("\n");
        X509_NAME_print_ex_fp(stdout, X509_get_subject_name(pX509),
                              1, XN_FLAG_MULTILINE);
        printf("\n\n");

        X509_free(pX509);
    }

    client->is_started = TRUE;
    
    return DTLS_OK;

_ERROR:
    dtls_uninitClient(client);
    return DTLS_FAIL;
}

int dtls_stopClient(dtlsClient* client)
{
    check_if(client == NULL, return DTLS_FAIL, "client is null");
    check_if(client->is_started == FALSE, return DTLS_FAIL, 
             "client is stopped");

    SSL_shutdown(client->ssl);
    client->is_started = FALSE;

    return DTLS_OK;
}

int dtls_sendData(dtlsClient* client, void* data, int data_len)
{
    check_if(client == NULL, return -1, "client is null");
    check_if(data == NULL,   return -1, "data is null");
    check_if(data_len <= 0,  return -1, "data_len = %d", data_len);

    check_if(client->is_started == FALSE, return -1, 
            "client is not started yet");

    check_if(_isDtlsAlive(client->ssl) == FALSE, return -1, 
            "client's ssl is not alive");
    
    int writelen;
    int check;

    writelen = SSL_write(client->ssl, data, data_len);
    check    = _checkSslWrite(client->ssl, data, writelen);
    check_if(check != DTLS_OK, return -1, "_checkSslWrite failed");

    return writelen;
}

int dtls_initSystem(void)
{
    _mutex_buf = (pthread_mutex_t*)calloc(sizeof(pthread_mutex_t),
                                          CRYPTO_num_locks());
    check_if(_mutex_buf == NULL, return DTLS_FAIL, "calloc failed");

    int i;
    for (i=0; i<CRYPTO_num_locks(); i++)
    {
        pthread_mutex_init(&_mutex_buf[i], NULL);
    }

    CRYPTO_set_id_callback(_dtlsIdCallback);
    CRYPTO_set_locking_callback(_sslLockFunc);

    return DTLS_OK;
}

void dtls_uninitSystem(void)
{
    check_if(_mutex_buf == NULL, return, "_mutex_buf is null");

    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);

    int i;
    for (i=0; i<CRYPTO_num_locks(); i++)
    {
        pthread_mutex_destroy(&_mutex_buf[i]);
    }

    free(_mutex_buf);
    _mutex_buf = NULL;

    return;
}

