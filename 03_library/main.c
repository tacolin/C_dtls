
#include "dtls.h"

#include <sys/select.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

////////////////////////////////////////////////////////////////////////////////

#define BUFFER_SIZE 2048

#define CLIENT_DEFAULT_TIMEOUT 5
#define SERVER_DEFAULT_TIMEOUT 5

////////////////////////////////////////////////////////////////////////////////

#define dprint(a, b...) fprintf(stdout, "%s(): "a"\n", __func__, ##b)
#define derror(a, b...) fprintf(stderr, "[ERROR] %s(): "a"\n", __func__, ##b)

#define check_if(assertion, error_action, ...) \
{\
    if (assertion) \
    { \
        derror(__VA_ARGS__); \
        {error_action;} \
    }\
}

////////////////////////////////////////////////////////////////////////////////

static const int _port    = 23232;
static int       _running = 1;

////////////////////////////////////////////////////////////////////////////////

static void _client(char* remote_ip, int remote_port);
static void _server(int local_port);

static void _sigIntHandler(int sigNum)
{
    _running = 0;
    dprint("stop main() while loop");
}

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
        _server(_port);
    }

    dtls_uninitSystem();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////

static void _server(int local_port)
{
    int    check;
    fd_set readset;
    int    select_ret;
    char   buffer[BUFFER_SIZE] = {0};
    int    recvlen;

    dtlsAddr client_addr = {};

    dtlsServer     server  = {};
    struct timeval timeout = {};
    struct timeval dtls_timeout = {
        .tv_sec  = SERVER_DEFAULT_TIMEOUT,
        .tv_usec = 0,
    };

    check = dtls_initServer(NULL, local_port,
                            "certs/server-cert.pem",
                            "certs/server-key.pem",
                            dtls_timeout, &server);
    check_if(check != DTLS_OK, return, "dtls_initServer failed");

    check = dtls_startServer(&server);

    while (_running)
    {
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        FD_ZERO(&readset);
        FD_SET(server.fd, &readset);

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
            if (FD_ISSET(server.fd, &readset))
            {
                recvlen = dtls_recvData(&server, buffer, BUFFER_SIZE, &client_addr);
                if (recvlen <= 0)
                {
                    derror("dtls_recvData failed");
                    break;
                }

                dprint("select recv : %s", buffer);
            }
        }
    }

    dtls_stopServer(&server);
    dtls_uninitServer(&server);

    return;
}

static void _client(char* remote_ip, int remote_port)
{
    dtlsClient client = {};
    struct timeval timeout = {
        .tv_sec = CLIENT_DEFAULT_TIMEOUT,
        .tv_usec = 0,
    };

    int  check;

    dprint("client open");

    check = dtls_initClient(remote_ip, remote_port,
                            "certs/client-cert.pem",
                            "certs/client-key.pem",
                            timeout, &client);
    check_if(check != DTLS_OK, return, "dtls_initClient failed");

    check = dtls_startClient(&client);
    check_if(check != DTLS_OK, return, "dtls_startClient failed");

    char buffer[BUFFER_SIZE] = {};
    int  writelen = 0;
    int  i;

    for (i=0; i<200 && _running; i++)
    {
        sprintf(buffer, "message No. %d", i);
        writelen = dtls_sendData(&client, buffer, strlen(buffer)+1);
        if (writelen > 0)
        {
            dprint("send : %s", buffer);
        }
        else
        {
            derror("send failed");
            goto _END;
        }

        sleep(1);
    }

_END:
    dtls_stopClient(&client);
    dtls_uninitClient(&client);
    dprint("client closed.");
    return;
}
