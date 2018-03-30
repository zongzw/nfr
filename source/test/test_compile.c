#define _GNU_SOURCE
#define HAVE_SNPRINTF
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <hiredis.h>
#include <locale.h>
#include <monetary.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <pcap-int.h>
#include <pthread.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pfring.h"
#include "pfutils.c"
#include "pfring_mod_sysdig.h"

#include "third-party/sort.c"
#include "third-party/node.c"
#include "third-party/ahocorasick.c"

int main(int argc, char **argv) {
    return 0;
}

/*
 /root/nfr/source/../dep/PF_RING-6.4.1/userland/lib/libpfring.a(pfring.o): In function `pfring_loop':
 pfring.c:(.text+0x1c2): undefined reference to `bpf_filter'
 /root/nfr/source/../dep/PF_RING-6.4.1/userland/lib/libpfring.a(pfring.o): In function `pfring_recv':
 pfring.c:(.text+0x5fb): undefined reference to `bpf_filter'
 /root/nfr/source/../dep/PF_RING-6.4.1/userland/lib/libpfring.a(pfring_mod.o): In function `pfring_mod_set_bpf_filter':
 pfring_mod.c:(.text+0xce3): undefined reference to `pcap_compile_nopcap'
 pfring_mod.c:(.text+0xd26): undefined reference to `pcap_freecode'
 /root/nfr/source/../dep/PF_RING-6.4.1/userland/lib/libpfring.a(pfring_utils.o): In function `pfring_parse_bpf_filter':
 pfring_utils.c:(.text+0x1875): undefined reference to `pcap_compile_nopcap'
 /root/nfr/source/../dep/PF_RING-6.4.1/userland/lib/libpfring.a(pfring_utils.o): In function `pfring_free_bpf_filter':
 pfring_utils.c:(.text+0x18a1): undefined reference to `pcap_freecode'
 collect2: error: ld returned 1 exit status
 make: *** [v3_n2r2p2s] Error 1
 
 */

/*
 Solution:
 change the Makefile for libpfring to remove the two definition. 
 
 ~/nfr/dep/PF_RING-6.4.1/userland/lib
 
 64 # by zongzw @2016.09.06
 65 # temporarily don't enable bpf and zc
 66 #CFLAGS    =  -march=native -mtune=native  -Wall -fPIC ${INCLUDE} -D HAVE_PF_RING_ZC     -D ENABLE_BPF  -D ENABLE_HW_TIMESTAMP -D HAVE_NT  -O2 # -g
 67 CFLAGS    =  -march=native -mtune=native  -Wall -fPIC ${INCLUDE} -D ENABLE_HW_TIMESTAMP -D HAVE_NT  -O2 # -g
 
 However, there should be a better way to do that. 
 Also if we use BPF and pcap_*, this should not work. 
 */