#!/usr/bin/env bash

gcc -fPIC -Werror -shared -g -pthread dtls.c -o libdtls.so -lcrypto -lssl

gcc -L./ -Werror -Wl,-rpath=./ -g dtls_test.c -o dtls_test -ldtls
