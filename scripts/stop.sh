#!/bin/bash

workdir=$(cd "$(dirname "$0")/.."; pwd)

kill -9 `pidof tcpflow`
kill -2 `pidof nfr`
