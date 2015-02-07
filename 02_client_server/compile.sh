#!/usr/bin/env bash

gcc -g -pthread main.c dtls.c -o main -lcrypto -lssl
