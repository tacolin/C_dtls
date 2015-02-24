#!/usr/bin/env bash

gcc -Werror -shared -g -pthread dtls.c -o libdtls.so -lcrypto -lssl

gcc -L./ -Werror -Wl,-rpath=./ -g -pthread main.c -o main -ldtls
