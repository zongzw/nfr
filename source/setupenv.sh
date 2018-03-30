#!/bin/bash 

workdir=$(cd "$(dirname "$0")/.."; pwd)

# 1. load pf_ring.ko
echo "insmod pf_ring.ko"
lsmod | grep pf_ring
if [ $? -ne 0 ]; then 
	insmod $workdir/bin/pf_ring.ko
fi

# 2. setup hugepages
echo "setup hugepages"
HUGEPAGES=1024
if [ `cat /proc/mounts | grep hugetlbfs | wc -l` -eq 0 ]; then
	sync && echo 3 > /proc/sys/vm/drop_caches
	echo $HUGEPAGES > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
	mkdir -p /mnt/huge
	mount -t hugetlbfs nodev /mnt/huge
fi
