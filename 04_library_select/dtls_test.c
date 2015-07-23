#include "dtls.h"

#include <signal.h>
#include <string.h>
#include <sys/select.h>

#define MAX_CONN_NUM (10)

#define dprint(a, b...) fprintf(stdout, "%s(): "a"\n", __func__, ##b)
#define derror(a, b...) fprintf(stderr, "[ERROR] %s(): "a"\n", __func__, ##b)

static int _running = 1;
static struct dtls_server _server = {};

static void _sigIntHandler(int sig_num)
{
    _running = 0;
    _server.accept_run = 0;
    dprint("stop main()");
}

static void _runDtlsClient(char* remote_ip, int remote_port, int local_port)
{
    struct dtls client = {};

    dtls_client_init(&client, remote_ip, remote_port, local_port, "certs/client-cert.pem", "certs/client-key.pem", 10);

    char buffer[256];
    int sendlen;
    int i;
    int recvlen;

    for (i=0 ; i<50 && _running; i++)
    {
        sprintf(buffer, "data %d", i);
        sendlen = dtls_send(&client, buffer, strlen(buffer)+1);
        if (sendlen <= 0)
        {
            derror("sendlen = %d", sendlen);
            break;
        }

        sleep(1);

        recvlen = dtls_recv(&client, buffer, 256);
        if (recvlen <= 0)
        {
            derror("recv echo len = %d", recvlen);
            break;
        }
        dprint("recv echo = %s", buffer);
    }

    dtls_client_uninit(&client);
    return;
}

static void _runDtlsServer(int local_port)
{
    dtls_server_init(&_server, NULL, local_port, "certs/server-cert.pem", "certs/server-key.pem", 10);

    char buffer[256];
    int  recvlen;
    int  sendlen;

    struct dtls    dtls[MAX_CONN_NUM] = {0};
    struct timeval timeout = {};
    int            sel_ret;
    fd_set         readset;
    int i;

    while (_running)
    {
        timeout.tv_sec  = 1;
        timeout.tv_usec = 0;

        FD_ZERO(&readset);
        FD_SET(_server.fd, &readset);

        for (i=0; i<MAX_CONN_NUM; i++)
        {
            if (dtls[i].is_init)
            {
                FD_SET(dtls[i].fd, &readset);
            }
        }

        sel_ret = select(FD_SETSIZE, &readset, NULL, NULL, &timeout);
        if (sel_ret == 0)
        {
            continue;
        }
        else if (sel_ret > 0)
        {
            for (i=0; i<MAX_CONN_NUM; i++)
            {
                if ((dtls[i].is_init) && FD_ISSET(dtls[i].fd, &readset))
                {
                    recvlen = dtls_recv(&dtls[i], buffer, 256);
                    if (recvlen <= 0)
                    {
                        derror("recvlen = %d", recvlen);
                        dtls_client_uninit(&dtls[i]);
                        break;
                    }

                    dprint("rx (%s) from ip(%s) port(%d)", buffer,
                        dtls[i].remote.ipv4, dtls[i].remote.port);

                    sendlen = dtls_send(&dtls[i], buffer, recvlen);
                    if (sendlen <= 0)
                    {
                        derror("send echo back len = %d", sendlen);
                        dtls_client_uninit(&dtls[i]);
                        break;
                    }
                }
            }

            if (FD_ISSET(_server.fd, &readset))
            {
                for (i=0; i<MAX_CONN_NUM; i++)
                {
                    if (dtls[i].is_init == 0)
                    {
                        int chk = dtls_server_accept(&_server, &dtls[i]);
                        break;
                    }
                }
            }
        }
        else
        {
            derror("select failed");
            break;
        }
    }

    for (i=0; i<MAX_CONN_NUM; i++)
    {
        if (dtls[i].is_init) dtls_client_uninit(&dtls[i]);
    }

    dtls_server_uninit(&_server);
    return;
}

int main(int argc, char const *argv[])
{
    signal(SIGINT, _sigIntHandler);

    if (argc == 2)
    {
        //////////////////////////////////////////////
        //  Server Mode
        //  ./test_dtls [local port]
        //
        //  for example:
        //  ./test_dtls 50000
        //////////////////////////////////////////////
        int port = atoi(argv[1]);
        _runDtlsServer(port);
    }
    else if (argc >= 3)
    {
        /////////////////////////////////////////////////////////////
        //  Client Mode
        //  ./test_dtls [remote_ip] [remote_port] [local_port]
        //
        //  for example:
        //  ./test_dtls 192.168.20.10 50000 40000
        //  ./test_dtls 192.168.20.10 50000 -> local_port is random
        /////////////////////////////////////////////////////////////
        int remote_port = atoi(argv[2]);
        int local_port = DTLS_PORT_ANY;

        if (argc == 4)
        {
            local_port = atoi(argv[3]);
        }

        _runDtlsClient( (char*)argv[1], remote_port, local_port);
    }

    return 0;
}
