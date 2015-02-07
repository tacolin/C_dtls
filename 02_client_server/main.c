
#include "basic.h"
#include "dtls.h"

#include <sys/un.h>
#include <sys/select.h>

typedef struct connArg
{
    int unfd;
    struct sockaddr_un unaddr;

} connArg;

////////////////////////////////////////////////////////////////////////////////

static const int _port       = 23232;
static int _is_server_running = 1;

////////////////////////////////////////////////////////////////////////////////

static void _client(char* remote_ip, int remote_port);
static void _recvCallback(void* conn_info);

static void _sigIntHandler(int sigNum)
{
    _is_server_running = 0;
    dprint("stop main() while loop");
}

static connArg _createUnixSocketClient(char* path);
static connArg _createUnixSocketServer(char* path);

////////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    int check;

    signal(SIGINT, _sigIntHandler);

    check = dtls_initSystem();
    check_if(check != DTLS_OK, return -1, "dtls_initSystem failed");

    if (argc >= 2)
    {
        _client(argv[1], _port);
    }
    else
    {
        dtlsServer server = {};
        int check;

        connArg un_client = _createUnixSocketClient("tacolin");
        check_if(un_client.unfd < 0, return, "_createUnixSocketClient failed");

        check = dtls_initServer(NULL, _port, _recvCallback, &un_client, sizeof(connArg), &server);
        check_if(check != DTLS_OK, close(un_client.unfd); return, "dtls_initServer failed");

        connArg un_server = _createUnixSocketServer("tacolin");
        check_if(un_client.unfd < 0, close(un_client.unfd); return, "_createUnixSocketClient failed");

        fd_set readset;
        int   select_ret;
        struct timeval timeout;
        char buffer[BUFFER_SIZE] = {0};
        int  recvlen;
        int  addrlen;
        struct sockaddr_un unused;

        dtls_startServer(&server);

        while (_is_server_running)
        {
            addrlen = sizeof(struct sockaddr_un);

            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            FD_ZERO(&readset);
            FD_SET(un_server.unfd, &readset);

            select_ret = select(FD_SETSIZE, &readset, NULL, NULL, &timeout);
            if (select_ret < 0)
            {
                derror("select failed");
                break;
            }
            else if (select_ret == 0)
            {
                continue;
            }
            else
            {
                if (FD_ISSET(un_server.unfd, &readset))
                {
                    recvlen = recvfrom(un_server.unfd, buffer, BUFFER_SIZE, 0,
                                       (struct sockaddr*)&unused, &addrlen);
                    if (recvlen <= 0)
                    {
                        derror("recvfrom failed");
                        break;
                    }

                    dprint("select recv : %s", buffer);
                }
            }
        }

        dtls_stopServer(&server);
        dtls_uninitServer(&server);

        close(un_client.unfd);
        close(un_server.unfd);

        unlink("tacolin");
    }

    dtls_uninitSystem();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////

static connArg _createUnixSocketClient(char* path)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    check_if(fd < 0, goto _ERROR, "socket failed");

    struct sockaddr_un server = {.sun_family = AF_UNIX};
    strncpy(server.sun_path, path, sizeof(server.sun_path) - 1);

    return (connArg){.unfd = fd, .unaddr = server};

_ERROR:
    if (fd > 0)
    {
        close(fd);
    }
    return (connArg){.unfd = -1};
}

static connArg _createUnixSocketServer(char* path)
{
    unlink(path);

    int check;
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    check_if(fd < 0, goto _ERROR, "socket failed");

    struct sockaddr_un local = {.sun_family = AF_UNIX};
    strncpy(local.sun_path, path, sizeof(local.sun_path) - 1);

    check = bind(fd, (struct sockaddr*)&local, sizeof(struct sockaddr_un));
    check_if(check < 0, goto _ERROR, "bind failed");

    return (connArg){.unfd = fd, .unaddr = local};

_ERROR:
    if (fd > 0)
    {
        close(fd);
    }
    return (connArg){.unfd = -1};
}

static void _recvCallback(void* conn_info)
{
    int  i;
    char buffer[BUFFER_SIZE] = {0};
    int  readlen;
    int  sendlen;
    int  check;
    SSL* ssl;
    dtlsConnInfo* info = (dtlsConnInfo*)conn_info;
    connArg* arg;

    check_if(info == NULL, goto _END, "info is null");

    ssl = info->ssl;
    check_if(ssl == NULL, goto _END, "ssl is null");

    arg = info->conn_arg;
    check_if(arg == NULL, goto _END, "arg is null");

    while (dtls_isAlive(ssl))
    {
        readlen = SSL_read(ssl, buffer, BUFFER_SIZE);
        check = dtls_checkSslRead(ssl, buffer, readlen);
        if (check == DTLS_FAIL)
        {
            derror("dtls_checkSslRead failed");
            goto _END;
        }
        else if (check == DTLS_END)
        {
            dprint("dtls end");
            goto _END;
        }

        dprint("read : %s", buffer);

        sendlen = sendto(arg->unfd, buffer, readlen, 0, (struct sockaddr*)&arg->unaddr,
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

static void _client(char* remote_ip, int remote_port)
{
    dtlsClient client = {};
    int  check;

    dprint("client open");

    check = dtls_initClient(remote_ip, remote_port, &client);
    check_if(check != DTLS_OK, return, "dtls_initClient failed");

    char buffer[BUFFER_SIZE] = {};
    int  readlen;
    int  writelen;
    int  reading_flag = 0;
    int  i;

    for (i=0; (i<200) && dtls_isAlive(client.ssl); i++)
    {
        sprintf(buffer, "message No. %d", i);
        writelen = SSL_write(client.ssl, buffer, strlen(buffer)+1);
        if (dtls_checkSslWrite(client.ssl, buffer, writelen) != DTLS_OK)
        {
            derror("dtls_checkSslWrite failed");
            goto _END;
        }

        dprint("send : %s", buffer);
    }

_END:
    SSL_shutdown(client.ssl);
    dtls_uninitClient(&client);
    dprint("client closed.");
    return;
}
