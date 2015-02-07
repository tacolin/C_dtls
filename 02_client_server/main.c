
#include "basic.h"
#include "dtls.h"

////////////////////////////////////////////////////////////////////////////////

static const int _port       = 23232;
static int _is_server_running = 1;

////////////////////////////////////////////////////////////////////////////////

static void _client(char* remote_ip, int remote_port);
static void _recvCallback(SSL* ssl);

static void _sigIntHandler(int sigNum)
{
    _is_server_running = 0;
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
        dtlsServer server = {};
        int check;

        check = dtls_initServer(NULL, _port, _recvCallback, &server);
        check_if(check != DTLS_OK, return, "dtls_initServer failed");

        dtls_startServer(&server);

        while (_is_server_running)
        {
            sleep(1);
        }

        dtls_stopServer(&server);
        dtls_uninitServer(&server);
    }

    dtls_uninitSystem();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////

static void _recvCallback(SSL* ssl)
{
    int  i;
    char buffer[BUFFER_SIZE] = {0};
    int  readlen;
    int  writelen;
    int  check;

    check_if(ssl == NULL, goto _END, "ssl is null");

    // for (i=0; (i<200) && dtls_isAlive(ssl); i++)
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
