/*
 * (C) 2003-15 - ntop
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

//#define _GNU_SOURCE
#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "pfring.h"

pcap_dumper_t *dumper = NULL;


/* ****************************************************** */

void dummyProcesssPacket(const struct pfring_pkthdr *h,
                         const u_char *p, const u_char *user_bytes) {
    //long threadId = (long)user_bytes;
    //u_int8_t dump_match = 0;
    
    //stats->numPkts[threadId]++, stats->numBytes[threadId] += h->len+24 /* 8 Preamble + 4 CRC + 12 IFG */;
    
    
    //if(unlikely(automa != NULL)) {
        //if((h->caplen > 42 /* FIX: do proper parsing */)
          //// && (search_string((char*)&p[42], h->caplen-42) == 1)) {
            
                pcap_dump((u_char*)dumper, (struct pcap_pkthdr*)h, p);
                //pcap_dump_flush(dumper);
            
        //}
    ///}
    
}


#define NO_ZC_BUFFER_LEN 65536

void print_buff(void *buff, long bufflen) {
    long i;
    printf("data: len = %ld\n", bufflen);
    char *buff_p = (char*)buff;
    for(i=0; i<bufflen; i++) {
        printf("%02x ", buff_p[i] & 255);
        if((i+1) % 16 == 0) printf("\n");
    }
    printf("\n");
}


static int stop = 0;
void sigproc(int sig) {
    printf("Leaving...\n");
    stop = 1;
}

int main(int argc, char **argv) {
    
    pfring  *pd;
    
    char *device = "eth0";
    
    int snaplen = NO_ZC_BUFFER_LEN;
    u_int32_t flags = 0;
    flags |= PF_RING_LONG_HEADER;
    
    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);
    int rc;
    packet_direction direction = rx_only_direction; //rx_and_tx_direction; //
    
    pd = pfring_open(device, snaplen, flags);
    if(pd == NULL) {
        fprintf(stderr, "pfring_open error [%s] (pf_ring not loaded or interface %s is down ?)\n",
                strerror(errno), device);
        return -1;
    }
    
    
    rc = pfring_set_cluster(pd, atoi(argv[1]), cluster_per_flow_tcp_5_tuple);
    printf("pfring_set_cluster returned %d\n", rc);
    
    if((rc = pfring_set_direction(pd, direction)) != 0)
    {
        printf("failed to set direction recv only.\n");
        //fprintf(stderr, "pfring_set_direction returned %d (perhaps you use a direction other than rx only with ZC?)\n", rc);
    }
    
    if (pfring_enable_ring(pd) != 0) {
        printf("Unable to enable ring :-(\n");
        pfring_close(pd);
        return(-1);
    }
    
    u_char buffer[NO_ZC_BUFFER_LEN];
    u_char *buffer_p = buffer;
    
    struct pfring_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    
    while(!stop) {
        int rc;
        
        if((rc = pfring_recv(pd, &buffer_p, NO_ZC_BUFFER_LEN, &hdr, 1)) > 0) {
            //print_packet(&hdr, buffer_p, 0);
            //pkt_num_count[threadid] ++;
            //pkt_bytes_count[threadid] += hdr.len;
            // to local huge mem
            printf("before parse \n");
            print_buff(&hdr, sizeof(hdr));
            
            //pfring_parse_pkt(buffer_p, &hdr, 4, 0, 0);
            
            //printf("after parse \n");
            //print_buff(&hdr, sizeof(hdr));
            
            printf("src:%d, dst:%d, sp:%d, dp:%d, proto: %d\n", hdr.extended_hdr.parsed_pkt.ip_src.v4,
                   hdr.extended_hdr.parsed_pkt.ip_dst.v4, hdr.extended_hdr.parsed_pkt.l4_src_port, hdr.extended_hdr.parsed_pkt.l4_dst_port, hdr.extended_hdr.parsed_pkt.l3_proto);
            
            //print_buff(buffer_p, hdr.caplen);
            
        }
    }
    
    
    pfring_close(pd);
    return 0;

}

/*
#define _GNU_SOURCE
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <monetary.h>
#include <locale.h>

#include "pfring.h"

#include "pfutils.c"

#include "pfring_mod_sysdig.h"

#include "third-party/sort.c"
#include "third-party/node.c"
#include "third-party/ahocorasick.c"

#define NO_ZC_BUFFER_LEN 65536

void print_buff(void *buff, long bufflen) {
    long i;
    for(i=0; i<bufflen; i++) {
        printf("%02x ", *(u_char*)buff & 255);
        if((i+1) % 16 == 0) printf("\n");
    }
}


static int stop = 0;
void sigproc(int sig) {
    printf("Leaving...\n");
    stop = 1;
}

int main(int argc, char **argv) {
    
    pfring  *pd;
    
    char *device = "eth0";
    
    int snaplen = NO_ZC_BUFFER_LEN;
    u_int32_t flags = 0;
    
    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);
    int rc;
    packet_direction direction = rx_only_direction;
    
    pd = pfring_open(device, snaplen, flags);
    if(pd == NULL) {
        fprintf(stderr, "pfring_open error [%s] (pf_ring not loaded or interface %s is down ?)\n",
                strerror(errno), device);
        return -1;
    }
    
    if((rc = pfring_set_direction(pd, direction)) != 0)
    {
        printf("failed to set direction recv only.\n");
        //fprintf(stderr, "pfring_set_direction returned %d (perhaps you use a direction other than rx only with ZC?)\n", rc);
    }
    
    if (pfring_enable_ring(pd) != 0) {
        printf("Unable to enable ring :-(\n");
        pfring_close(pd);
        return(-1);
    }
    
    u_char buffer[NO_ZC_BUFFER_LEN];
    u_char *buffer_p = buffer;
    
    struct pfring_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    
    while(!stop) {
        int rc;
        
        if((rc = pfring_recv(pd, &buffer_p, NO_ZC_BUFFER_LEN, &hdr, 1)) > 0) {
            //print_packet(&hdr, buffer_p, 0);
            //pkt_num_count[threadid] ++;
            //pkt_bytes_count[threadid] += hdr.len;
            // to local huge mem
            print_buff(buffer_p, hdr.caplen)
           
        }
    }
    
    
    pfring_close(pd);
    return 0;
    
    
}
*/