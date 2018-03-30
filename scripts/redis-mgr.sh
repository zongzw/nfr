#!/bin/bash

# $0 port cpu instances
if [ $# -eq 0 ]; then
    echo
    echo "[re]start redis:"
    echo "  $0 start <begin-port> <instances> <begin-cpu>"
    echo "  $0 start 6379 0 4: "
    echo "      start redis-server at 6379 6380 6381 6382, bind to cpu core at 0 1 2 3 separately."
    echo "      if instances > cpu core num, redis-server will bind to cpu core robin-cycly."
    echo
    echo "stop redis:"
    echo "  $0 stop <begin-port> <instances>"
    echo
    echo "cli redis:"
    echo "  $0 cli <port>"
    echo
fi

workdir=$(cd $(dirname $0)/..; pwd)
redishome=$workdir/bin/redis

start1() {
    local p=$1   # port
    local c=$2   # cpu
    local m=$3   # max cpu

    ps -ef | grep -v grep | grep redis-server | grep $p
    if [ $? -ne 0 ]; then 
        echo "start redis-server $p at $c"
        ($redishome/bin/redis-server --port $p &)
        retry=3
        while [ $retry -gt 0 ]; do
            retry=$(( $retry - 1 )) 
            ps -ef | grep -v grep | grep redis-server | grep $p
            if [ $? -ne 0 ]; then
                sleep 1
                echo "waiting for redis start .."
            else
                break;
            fi
        done
        if [ $retry -eq 0 ]; then 
            echo "**** Failed to start redis "
            exit 1
        fi
        pid=`ps -ef | grep redis-server | grep $p | tr -s ' ' | cut -d' ' -f2`
        taskset -p $((1<<($c%$m))) $pid
        echo
    else
        echo "redis-server at $p already running."
    fi
}

dostart() {
    local p=$1   # port
    local n=$2   # number of instance
    local c=$3   # cpu

    echo "start redis-server"
    if [ ! -f $redishome/bin/redis-server ]; then
        echo "redis binary not found. quit."
        exit 1
    fi
    echo 511 > /proc/sys/net/core/somaxconn
    echo never > /sys/kernel/mm/transparent_hugepage/enabled

    numcore=`cat /proc/cpuinfo | grep 'processor' | uniq -c | wc -l`
    echo "number of core: $numcore"
    for i in $(seq $p 1 $(($p + $n - 1))); do
        start1 $i $(($i - $p + $c)) $numcore
    done

    sleep 1
    ps -ef | grep redis-server | grep -v grep
    ps -eo pid,args,psr | grep redis | grep -v grep
    echo
}

stop1() {
    local p=$1   # port

    pid=`ps -ef | grep redis-server | grep $p | tr -s ' ' | cut -d' ' -f2`
    if [ -n "$pid" ]; then
        kill -9 $pid
        while true; do
            ps -ef | grep -v grep | grep redis-server | grep $p
            if [ $? -eq 0 ]; then
                echo "waiting for redis-server quit..."
                sleep 1
            else
                echo "redis-server $p quit."
                break
            fi
        done
    fi
}

dostop() {
    local p=$1
    local n=$2

    i=0
    while [ $i -lt $n ]; do
        stop1 $(($p + $i))
        i=$(($i + 1))
    done

}

action=$1
port=$2
instances=$3
cpu=$4

case $action in
stop)
    dostop $port $instances
    ;;
restart)
    dostop $port $instances
    dostart $port $instances $cpu
    ;;
cli)
    $redishome/bin/redis-cli -h 127.0.0.1 -p $port
    ;;
start)
    dostart $port $instances $cpu
    ;;
esac
