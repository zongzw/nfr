#!/bin/bash

if [ $# -ne 3 ]; then
    echo "$0 nic-name outdir numthr"
    exit 0
fi

nicname=$1
outdir=$2
numthr=$3

redisport=9379

workdir=$(cd "$(dirname "$0")/.."; pwd)

modprobe pf_ring

$workdir/bin/redis-mgr.sh restart $redisport $numthr 0
mkdir -p $outdir
#mount | grep -v grep | grep $outdir
#if [ $? -eq 0 ]; then
#    rm -rf $workdir/test/*
#else
#    mount -t tmpfs tmpfs $outdir
#fi

[ -n "$outdir" ] && rm -rf $outdir/*
mkdir -p $outdir/log

($workdir/bin/nfr -c 1677216 -p $redisport -w 0 -t $numthr -i $nicname -o $outdir -g $outdir/log -d rt -z 22,80,8000,8888,8080-8086,9000,9093,9096,25,110,21,8181 -f 20 &)
