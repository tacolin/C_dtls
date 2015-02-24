#!/usr/bin/env bash

gcc -Werror -shared -g -pthread dtls.c -o libdtls.so -lcrypto -lssl

gcc -L./ -Werror -Wl,-rpath=./ -g main.c -o main -ldtls
