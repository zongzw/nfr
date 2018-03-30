
workdir = $(CURDIR)/../..
hiredishome = $(workdir)/dep/hiredis
redishome = $(workdir)/dep/redis-3.2.3
pfringhome = $(workdir)/dep/PF_RING-6.4.1
influxhome = $(workdir)/dep/influxdb-c-master
sourcedir = $(workdir)/source

GDBFLAG = "-g"
O3FLAG = "-O0"
BPFFLAG = "-D ENABLE_BPF "
ZCFLAG = "-D HAVE_PF_RING_ZC "
#

all: testbin

clean:
	@echo "cleaning binaries ..."
	@rm -f *.o testbin/*

hiredis:
	@if [ ! -f $(hiredishome)/libhiredis.a ]; then \
		echo "compiling hiredis ..."; \
		cd $(hiredishome); make; fi

pf_ring:
	@if [ ! -f $(pfringhome)/kernel/pf_ring.ko ]; then \
		echo "compiling pf_ring ..."; \
        cp $(sourcedir)/libpfring_Makefile.in $(pfringhome)/userland/lib/Makefile.in; \
        cp $(sourcedir)/pfring_utils.c $(pfringhome)/userland/lib/pfring_utils.c; \
		cd $(pfringhome); make; fi

redis:
	@if [ ! -f $(redishome)/src/redis-server ]; then \
		echo "compiling redis ..."; \
		cd $(redishome); \
		make; \
		make PREFIX=$(workdir)/bin/redis install; \
	fi;

testbin: getopt set_cpu_affinity redis_perf string_handling pfring_api pfring_cluster pipe_to_tcpflow compile redis_pipeline

getopt:
	@gcc test_getopt.c -o testbin/getopt

set_cpu_affinity:
	@gcc -D_GNU_SOURCE test_set_cpu_affinity.c \
	-o testbin/set_cpu_affinity -lpthread

redis_pipeline: hiredis
	@gcc -std=gnu99 test_redis_pipeline.c \
	-I$(hiredishome) \
	-L$(hiredishome) -lhiredis -lpthread -lcrypto \
	-o testbin/redis_pipeline 

redis_perf: hiredis
	@gcc -std=gnu99 test_redis_perf.c \
	-I$(hiredishome) \
	-L$(hiredishome) -lhiredis -lpthread -lcrypto \
	-o testbin/redis_perf 

string_handling:
	@gcc test_string_handling.c -o testbin/string_handling

pfring_api: pf_ring
	@gcc $(GDBFLAG) -march=native -mtune=native  $(O3FLAG) -DHAVE_PF_RING -Wall \
	-I$(pfringhome)/kernel -I$(pfringhome)/kernel/plugins \
	-I$(pfringhome)/userland/lib -I$(pfringhome)/userland/libpcap \
	-I$(pfringhome)/userland/examples \
	$(BPFFLAG) $(ZCFLAG)  test_pfring_api.c \
	$(pfringhome)/userland/libpcap/libpcap.a  $(pfringhome)/userland/lib/libpfring.a \
	-lpthread -L/opt/napatech3/lib -lntapi -lntos -lrt -o testbin/pfring_api

pfring_cluster: pf_ring
	@gcc $(GDBFLAG) -march=native -mtune=native  $(O3FLAG) -DHAVE_PF_RING -Wall \
	-I$(pfringhome)/kernel -I$(pfringhome)/kernel/plugins \
	-I$(pfringhome)/userland/lib -I$(pfringhome)/userland/libpcap \
	-I$(pfringhome)/userland/examples \
	$(BPFFLAG) $(ZCFLAG)  test_pfring_cluster.c \
	$(pfringhome)/userland/libpcap/libpcap.a  $(pfringhome)/userland/lib/libpfring.a \
	-lpthread -L/opt/napatech3/lib -lntapi -lntos -lrt -o testbin/pfring_cluster

pipe_to_tcpflow:
	@gcc $(GDBFLAG) test_pipe_to_tcpflow.c -o testbin/pipe_to_tcpflow

compile: hiredis pf_ring
	@echo "compiling compile ..."
	@gcc $(GDBFLAG) -march=native -mtune=native -std=gnu99  $(O3FLAG) -DHAVE_PF_RING -Wall \
	-I$(pfringhome)/kernel -I$(pfringhome)/kernel/plugins \
	-I$(hiredishome) \
	-I$(pfringhome)/userland/lib -I$(pfringhome)/userland/libpcap \
	-I$(pfringhome)/userland/examples \
	$(BPFFLAG) $(ZCFLAG)  test_compile.c \
	$(pfringhome)/userland/libpcap/libpcap.a  $(pfringhome)/userland/lib/libpfring.a \
	-L$(hiredishome) -lhiredis \
	-lpthread -L/opt/napatech3/lib -lntapi -lntos -lrt -o testbin/compile

write2influxdb:
	@echo "compiling write to influxdb testbin ..."
	@gcc -I$(influxhome)/src test_write2influxdb.c -lpthread -o testbin/write2influxdb
