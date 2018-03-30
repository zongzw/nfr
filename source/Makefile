
workdir = $(CURDIR)/..
hiredishome = $(workdir)/dep/hiredis
redishome = $(workdir)/dep/redis-3.2.3
pfringhome = $(workdir)/dep/PF_RING-6.4.1
influxhome = $(workdir)/dep/influxdb-c-master
sourcedir = $(workdir)/source

GDBFLAG = "-g"
O3FLAG = "-O0"
BPFFLAG = "-D ENABLE_BPF "
ZCFLAG = "-D HAVE_PF_RING_ZC "
#BINLIST = v1_n2r v1_r2p v2_n2r v2_r2p nfr
BINLIST = nfr tcpstat
#

all: $(BINLIST) redis

install: redis pf_ring
	@cp $(sourcedir)/nfr $(workdir)/bin
	@cp $(sourcedir)/tcpstat $(workdir)/bin
	@cd $(redishome); make PREFIX=$(workdir)/bin/redis install;
	@cp $(pfringhome)/kernel/pf_ring.ko $(pfringhome)/userland/lib/libpfring.a \
		$(pfringhome)/userland/lib/libpfring.so $(workdir)/bin
	@cp $(sourcedir)/setupenv.sh $(workdir)/bin
	@cd $(pfringhome)/userland/lib; make install

clean:
	@echo "cleaning binaries ..."
	@rm -f $(BINLIST); \
	rm -rf $(workdir)/bin/*; \
	(cd $(sourcedir); rm -f $(BINLIST)); \
	rm -f *.o testbin/*; \
	echo "cd $(pfringhome); make clean"; \
	(cd $(pfringhome); make clean); \
	echo "cd $(hiredishome); make clean"; \
	(cd $(hiredishome); make clean); \
	echo "cd $(redishome); make clean"; \
	(cd $(redishome); make clean);

tcpstat: hiredis pf_ring
	@echo "compiling tcpstat ..."
	@gcc $(GDBFLAG) -march=native -mtune=native -std=gnu99  $(O3FLAG) -DHAVE_PF_RING -Wall \
	-I$(pfringhome)/kernel -I$(pfringhome)/kernel/plugins \
	-I$(hiredishome) \
	-I$(pfringhome)/userland/lib -I$(pfringhome)/userland/libpcap \
	-I$(pfringhome)/userland/examples \
	$(BPFFLAG) $(ZCFLAG) -O2  tcpstat.c \
	$(pfringhome)/userland/libpcap/libpcap.a  $(pfringhome)/userland/lib/libpfring.a \
	-L$(hiredishome) -lhiredis -lcurses \
	-lpthread -levent -L/opt/napatech3/lib -lntapi -lntos -lrt -o tcpstat

nfr: hiredis pf_ring
	@echo "compiling nfr ..."
	@gcc $(GDBFLAG) -march=native -mtune=native -std=gnu99  $(O3FLAG) -DHAVE_PF_RING -Wall \
	-I$(pfringhome)/kernel -I$(pfringhome)/kernel/plugins \
	-I$(hiredishome) \
	-I$(pfringhome)/userland/lib -I$(pfringhome)/userland/libpcap \
	-I$(pfringhome)/userland/examples \
	$(BPFFLAG) $(ZCFLAG) -O2  nfr.c \
	$(pfringhome)/userland/libpcap/libpcap.a  $(pfringhome)/userland/lib/libpfring.a \
	-L$(hiredishome) -lhiredis -lcurses \
	-lpthread -L/opt/napatech3/lib -lntapi -lntos -lrt -o nfr

v2_r2p: hiredis
	@echo "compiling v2_r2p ..."
	@gcc $(GDBFLAG) -std=gnu99 $(O3FLAG) -Wall \
	-I$(pfringhome)/userland/libpcap \
	v2_r2p.c -I$(hiredishome) -L$(hiredishome) -lhiredis -lpthread \
	-o v2_r2p
	@chmod +x $(sourcedir)/v2_r2p

v2_n2r: pf_ring
	@echo "compiling v2_n2r ..."
	@gcc $(GDBFLAG) -march=native -mtune=native $(O3FLAG) -DHAVE_PF_RING -Wall \
	-I$(pfringhome)/kernel -I$(pfringhome)/kernel/plugins \
	-I$(hiredishome) \
	-I$(pfringhome)/userland/lib -I$(pfringhome)/userland/libpcap \
	-I$(pfringhome)/userland/examples \
	$(BPFFLAG) $(ZCFLAG)  v2_n2r.c \
	$(pfringhome)/userland/libpcap/libpcap.a  $(pfringhome)/userland/lib/libpfring.a \
	-L$(hiredishome) -lhiredis \
	-lpthread -L/opt/napatech3/lib -lntapi -lntos -lrt -o v2_n2r

v1_r2p: hiredis
	@echo "compiling v1_r2p ..."
	@gcc $(GDBFLAG) -std=gnu99 ${O3FLAG} -Wall \
	v1_r2p.c -I$(hiredishome) -L$(hiredishome) -lhiredis -lpthread \
	-o v1_r2p
	@chmod +x $(sourcedir)/v1_r2p

v1_n2r: pf_ring
	@echo "compiling v1_n2r ..."
	@gcc $(GDBFLAG) -march=native -mtune=native $(O3FLAG) -DHAVE_PF_RING -Wall \
		-I$(hiredishome) \
		-I$(pfringhome)/kernel \
		-I$(pfringhome)/kernel/plugins \
		-I$(pfringhome)/userland/lib \
		-I$(pfringhome)/userland/libpcap \
		-I$(pfringhome)/userland/examples/third-party \
		$(BPFFLAG) $(ZCFLAG)  \
		-c v1_n2r.c -o v1_n2r.o
	@gcc $(GDBFLAG) -march=native -mtune=native  $(O3FLAG) -DHAVE_PF_RING -Wall \
		$(BPFFLAG) $(ZCFLAG)  \
		v1_n2r.o \
		-L$(pfringhome)/userland/libpcap -lpcap \
		-L$(pfringhome)/userland/lib -lpfring \
		-L$(hiredishome) -lhiredis \
		-lpthread  \
		-o v1_n2r

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

