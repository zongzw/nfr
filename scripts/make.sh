#!/bin/bash

dstdir=$(cd $(dirname $0)/..; pwd)
#srcdir=/media/nfr
srcdir=/media/svndir/1.3-Code/Pkt2Redis2Pcap

if [ -d $srcdir ]; then 
    echo "$srcdir/* --> $dstdir"
    cp -r $srcdir/* $dstdir
	if [ $? -ne 0 ]; then 
		echo "Failed to copy file from $srcdir to $dstdir";
		exit 1
	fi
else
	echo "No copy happens.";
fi

workdir=$dstdir

(
	cd $workdir/source
	make $@
)

for n in redis-mgr.sh start.sh stop.sh; do
    cp $workdir/scripts/$n $workdir/bin
done

