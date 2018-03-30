#!/bin/bash

API_URL="http://localhost:8086"

echo "=> Starting influxd to backgroud."
exec /usr/bin/influxd &
#wait for the startup of influxdb
RET=1
while [[ RET -ne 0 ]]; do
    echo "=> Waiting for confirmation of InfluxDB service startup ..."
    sleep 3 
    curl -k ${API_URL}/ping 2> /dev/null
    RET=$?
done
echo ""

#Pre create database on the initiation of the container
if [ -n "${PRE_CREATE_DB}" ]; then
    echo "=> About to create the following database: ${PRE_CREATE_DB}"
    arr=$(echo ${PRE_CREATE_DB} | tr ";" "\n")

    for x in $arr; do
        if [ -z "$x" ]; then continue; fi
        echo "=> Creating database: ${x}"
        echo "create database \"$x\"" | influx
        #curl -G 'http://localhost:8086/query?u=root&p=root' --data-urlencode "q=CREATE DATABASE ${x}"
        #curl -s -k -X POST -d "{\"name\":\"${x}\"}" $(echo ${API_URL}'/db?u=root&p='${PASS})
    done
    echo ""
else
    echo "=> No database need to be pre-created"
fi

while true; do
    sleep 10
done

