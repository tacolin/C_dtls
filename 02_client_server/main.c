
#include "basic.h"
#include "dtls.h"

#include <sys/select.h>

typedef struct unConnArg
{
    int unfd;
    struct sockaddr_un unaddr;

} unConnArg;

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

    dtlsServer     server  = {};
    struct timeval timeout = {};

    check = dtls_initServer(NULL, local_port, &server);
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
                recvlen = dtls_recvData(&server, buffer, BUFFER_SIZE);
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
    int  check;

    dprint("client open");

    check = dtls_initClient(remote_ip, remote_port, &client);
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
