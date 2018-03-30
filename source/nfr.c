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
#include <net/ethernet.h>     /* the L2 protocols */
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
#include <stdarg.h>

//#include <curses.h>

#include "pfring.h"
#include "pfutils.c"

#include "third-party/sort.c"
#include "third-party/node.c"
#include "third-party/ahocorasick.c"

#define DEFAULT_SNAPLEN         65535
#define MAX_NUM_THREADS         64
#define DEFAULT_DEVICE          "eth0"
#define MAX_PKT_SIZE            65535
#define TCPDUMP_MAGIC           0xa1b2c3d4
#define DEFAULT_NUM_THREADS     4
#define DEFAULT_CACHE_SIZE      1048576  // 1MB = 1048576
#define MAX_CACHE_SIZE          1024*1024*1024 // 1G
#define MIN_CACHE_SIZE          65535 + 16// max pkt size + sf hdr size
#define BYTES_PIPE              65536
#define	ETHERTYPE_IP            0x0800	/* IP protocol */
#define DEFAULT_STAT_INTERVAL   15
#define DEFAULT_FILTER_LIMIT    0
#define PRINT_ARG "tcp and not (dst port (22 or 445) or src port (22 or 445))"
#define MAX_ADDR_STRING_LENGTH  65536
#define MAX_FILTERING_RULE_COUNT 512
#define LQUIET  0
#define LINFO   1
#define LWARN   2
#define LERROR  3
#define LDEBUG  4

static int stop = 0;

static char outdir[256];
static int num_threads;
static pthread_t r2p2s_threads[MAX_NUM_THREADS];
static pthread_t n2r_threads[MAX_NUM_THREADS];
static pthread_t stat_thread;
static char device[16];
static int num_core;
static char host[256];
static int port;
static int wait_for_packet;
static int waittime;
static int cache_size;
static packet_direction direction;
static pfring *pds[MAX_NUM_THREADS];
static char bincmd[256];
static int verbose;
static char logdir[256];
static char influxdb[128];
static char infxuser[64];
static char infxpass[64];
static char dbname[64];
static char curlout[64];
static int stat_interval;
static int logfds[MAX_NUM_THREADS];
static int logfdm;
static struct timeval nowastat;
static long acptport[65537];
static char acptportstr[512];
static struct pcap_file_header pfh;
static int filter_limit;
static char srcaddrs[MAX_ADDR_STRING_LENGTH];
static char dstaddrs[MAX_ADDR_STRING_LENGTH];
static int filtering_rule_count;
static filtering_rule filtering_rule_list[MAX_FILTERING_RULE_COUNT];

typedef struct {
    int thrid;
    long recv_nPkts;
    long recv_nBytes;
    long ndroped;
    int core;
} n2r_stat_t;

typedef struct {
    int thrid;
    long queuelen;
} redis_stat_t;

typedef struct {
    int thrid;
    long nBytes;
    int cpuusage;
    int core;
} r2p2s_stat_t;

static n2r_stat_t n2rstat[MAX_NUM_THREADS];
static redis_stat_t redisstat[MAX_NUM_THREADS];
static r2p2s_stat_t r2p2sstat[MAX_NUM_THREADS];

extern char *optarg;
extern int optind, opterr, optopt;

void debug(int fd, char *fmt, ...);
void error(int fd, char *fmt, ...);
void warn(int fd, char *fmt, ...);
void info(int fd, char *fmt, ...);

void sigproc(int sig) {
    info(logfdm, "Leaving...");
    printf("Leaving ...\n");
    stop = 1;
}

void sigpipeproc(int sig) {
    info(logfdm, "SIGPIPE signal received. ");
    stop = 1;
}

void print_buff(void *buff, long bufflen) {
    long i;
    char *p = buff;
    //char buffline[64];
    //memset(buffline, 0, sizeof(buffline));
    for(i=0; i<bufflen; i++) {
        //sprintf(buffline+i, "%02x ", p[i] & 255);
        printf("%02x ", p[i] & 255);
        if((i+1) % 16 == 0) {
            //info(logfdm, buffline);
            printf("\n");
        }
    }
    printf("\n");
}

void get_pcap_file_header(int snaplen, struct pcap_file_header *hdr) {
    hdr->magic = TCPDUMP_MAGIC;
    hdr->version_major = PCAP_VERSION_MAJOR;
    hdr->version_minor = PCAP_VERSION_MINOR;
    
    hdr->thiszone = gmt_to_local(0);;
    hdr->snaplen = snaplen;
    hdr->sigfigs = 0;
    hdr->linktype = 1; // Ethernet, and Linux loopback devices
    //hdr->linktype = 9;  // ppp
}

redisContext* redis_connect(long threadid){
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    redisContext *c = redisConnectWithTimeout(host, port + threadid, timeout);
    if (c == NULL || c->err) {
        if (c) {
            error(logfdm, "Redis Connection error: %s, threadid: %ld", c->errstr, threadid);
            redisFree(c);
        } else {
            error(logfdm, "Connection error: can't allocate redis context.");
        }
        exit(1);
    }
    return c;
}

int should_drop(struct pkt_parsing_info *pktparsed) {
    // check if there exists ipv6 pkts and their l3_proto
    //if(pktparsed->eth_type == ETHERTYPE_IPV6) {
    //    printf("[ipv6 pkt %d]\n", pktparsed->l3_proto);
    //}
    //if(pktparsed->eth_type != ETHERTYPE_IP || pktparsed->l3_proto != 6) return 1;
    //printf("new pkt: src: %x, dst: %x, sport: %d, dport: %d, proto: %d\n", pktparsed->ip_src.v4, pktparsed->ip_dst.v4, pktparsed->l4_src_port, pktparsed->l4_dst_port, pktparsed->l3_proto);
    if(pktparsed->l3_proto != 6) return 1;
    if(acptport[pktparsed->l4_src_port] == 0 && acptport[pktparsed->l4_dst_port] == 0) return 1;
    
    if(acptport[pktparsed->l4_src_port]) acptport[pktparsed->l4_src_port] ++;
    if(acptport[pktparsed->l4_dst_port]) acptport[pktparsed->l4_dst_port] ++;
    
    
    long sum = pktparsed->ip_src.v4 + pktparsed->ip_dst.v4 + pktparsed->l4_src_port + pktparsed->l4_dst_port;
    if(sum % 100 < filter_limit) return 1;
    
    return 0;
}

void* produce_pkt_thread(void *args) {

    long threadid = (long) args;
    
    int core_id = threadid % num_core;
    if(bind2core(core_id) == 0) {
        info(logfds[threadid], "Set produce_pkt_thread on core %d/%d", core_id, num_core);
    }
    
    memset(&n2rstat[threadid], 0, sizeof(n2r_stat_t));
    n2rstat[threadid].thrid = threadid;
    n2rstat[threadid].core = core_id;
    
    u_char buffer[MAX_PKT_SIZE];
    u_char *buffer_p = buffer;
    
    struct pfring_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    
    u_char cache[cache_size];
    u_char *cache_p = cache;
    
    u_int32_t flags = 0;
    flags |= PF_RING_PROMISC;
    int snaplen = DEFAULT_SNAPLEN;
    
    pfring  *pd_in_thr;
    
    int rc;
    
    pd_in_thr = pfring_open(device, snaplen, flags);
    if(pd_in_thr == NULL) {
        error(logfds[threadid], "pfring_open error [%s] (pf_ring not loaded or interface %s is down ?)", strerror(errno), device);
        return NULL;
    }
    pds[threadid] = pd_in_thr;
    
    //rc = pfring_set_cluster(pd_in_thr, 1, cluster_per_flow_tcp_5_tuple);
    rc = pfring_set_cluster(pd_in_thr, 1, cluster_per_flow);
    info(logfds[threadid], "pfring_set_cluster returned %d", rc);
    
    if((rc = pfring_set_direction(pd_in_thr, direction)) != 0)
    {
        error(logfds[threadid], "failed to set direction recv only.");
    }
    /*
    char filter_buffer[] = {PRINT_ARG};
    if (pfring_set_bpf_filter(pd_in_thr, filter_buffer) != 0) {
        error(logfds[threadid], "set_BPF is failure!");
        //exit(EXIT_FAILURE);
        return NULL;
    }
    */
    if (pfring_enable_ring(pd_in_thr) != 0) {
        error(logfds[threadid], "Unable to enable ring :-(");
        pfring_close(pd_in_thr);
        return NULL;
    }
    
    redisContext *conn = redis_connect(threadid);
    redisReply *reply;
    struct timeval nowtime, lasttime;
    
    int waitmillsec = 500;
    gettimeofday(&lasttime, NULL);
    
    struct pcap_sf_pkthdr sfhdr;
    while(!stop) {
        
        //if((rc = pfring_recv(pd_in_thr, &buffer_p, MAX_PKT_SIZE, &hdr, wait_for_packet)) > 0) {
        memset(&hdr, 0, sizeof(hdr));
        if((rc = pfring_recv_parsed(pd_in_thr, &buffer_p, MAX_PKT_SIZE, &hdr, wait_for_packet, 4, 0, 0)) > 0) {
            
            struct pkt_parsing_info *pktparsed = &(hdr.extended_hdr.parsed_pkt);
            //printf("new pkt: src: %x, dst: %x, sport: %d, dport: %d, proto: %d\n", pktparsed->ip_src.v4, pktparsed->ip_dst.v4, pktparsed->l4_src_port, pktparsed->l4_dst_port, pktparsed->l3_proto);
            if(!should_drop(pktparsed)) {
                n2rstat[threadid].recv_nPkts ++;
                n2rstat[threadid].recv_nBytes += hdr.len;
            
                sfhdr.ts.tv_sec = hdr.ts.tv_sec;
                sfhdr.ts.tv_usec = hdr.ts.tv_usec;
                sfhdr.caplen = hdr.caplen;
                sfhdr.len = hdr.len;
                
                long hdrlen = sizeof(sfhdr);
                if(cache_p - cache + sizeof(sfhdr) + hdr.len > cache_size) {
                    reply = redisCommand(conn, "lpush %d %b", threadid, cache, cache_p - cache);
                    freeReplyObject(reply);
                    cache_p  = cache;
                    gettimeofday(&lasttime, NULL);
                }
                
                memcpy(cache_p, &sfhdr, hdrlen);
                cache_p += hdrlen;
                memcpy(cache_p, buffer_p, hdr.len);
                cache_p += hdr.len;
            }
        }
        else {
            if(wait_for_packet == 0) usleep(waittime);//sched_yield();
        }
        
        gettimeofday(&nowtime, NULL);
        
        if((cache_p != cache && nowtime.tv_sec-lasttime.tv_sec)*1000 + (nowtime.tv_usec-lasttime.tv_usec)/1000 > waitmillsec){
            lasttime.tv_sec = nowtime.tv_sec;
            lasttime.tv_usec = nowtime.tv_usec;
            
            reply = redisCommand(conn, "lpush %d %b", threadid, cache, cache_p - cache);
            freeReplyObject(reply);
            cache_p  = cache;
        }
    }
    
    info(logfds[threadid], "produce_pkt_thread quit.");
    redisFree(conn);
    pfring_close(pd_in_thr);
    pds[threadid] = 0;
    return NULL;
}

void* consume_pkt_thread(void* args) {
    long threadid = (long)args;
    
    int core_id = num_core - 1 - threadid % num_core;
    if(bind2core(core_id) == 0) {
        info(logfds[threadid], "Set consume_pkt_thread on core %d/%d", core_id, num_core);
    }
    
    memset(&r2p2sstat[threadid], 0, sizeof(r2p2s_stat_t));
    r2p2sstat[threadid].core = core_id;
    
    //redisContext *c;
    //c = redis_connect(threadid);
    //redisReply *pfhReply;
    //while(!stop) {
        /*
        pfhReply = redisCommand(c, "get pcap-file-header");
        if(pfhReply->type == REDIS_REPLY_NIL) {
            freeReplyObject(pfhReply);
            warn(logfds[threadid], "Delay starting r2p2s thread, waiting for redis message 'pcap-file-header' ...");
            usleep(100);
        }
        else {
            memset(&pfh, 0, sizeof(struct pcap_file_header));
            memcpy(&pfh, pfhReply->str, pfhReply->len);
            freeReplyObject(pfhReply);
            break;
        }
         */
    //}
    //redisFree(c);
    
    int rc;
    int pipes[2];
    rc = pipe(pipes);
    if(rc == -1) {
        error(logfds[threadid], "failed to create pipe");
        return NULL;
    }
    
    long left, once;
    long nBytesWrite = 0;
    char *write_p;
    
    pid_t pid;
    pid = fork();
    if(pid < 0) {
        error(logfds[threadid], "Failed: cannot fork sub process for tcpflow.");
        return NULL;
    }
    
    if(pid == 0) {
        close(pipes[1]);
        dup2(pipes[0], 0);
        
        char tcpflowcmd[256];
        int outlevel = (verbose == LDEBUG) ? 5 : (verbose == LQUIET) ? 0 : 1;
        
        sprintf(tcpflowcmd, "%s -d %d -r - -o %s/%ld > %s/tcpflow-%ld.log 2>&1", bincmd, outlevel, outdir, threadid, logdir, threadid);
        info(logfds[threadid], "tcpflow command: %s", tcpflowcmd);
        
        rc = system(tcpflowcmd);
        if(rc == 127 || rc <= 0) {
            error(logfds[threadid], "error while executing tcpflow command: %d: errno: %d.", rc, errno);
        }
        info(logfds[threadid], "tcpflow quit with %d, errno: %d.", rc, errno);
        close(pipes[0]);
    }
    else {
        close(pipes[0]);
        
        if(write(pipes[1], &pfh, sizeof(struct pcap_file_header)) != sizeof(struct pcap_file_header)) {
            error(logfds[threadid], "Failed to write pcap file header. parsing packets to session may failed.");
        }
        
        redisContext *c;
        c = redis_connect(threadid);
        redisReply *reply;
        
        while(!stop) {
            reply = redisCommand(c, "rpop %d", threadid);
            if(reply->type == REDIS_REPLY_NIL) {
                freeReplyObject(reply);
                //info(logfds[threadid], "redis queue is empty.");
                usleep(100);
                continue;
            }
            
            left = reply->len;
            write_p = reply->str;
            while(left > 0) {
                once = (left > BYTES_PIPE) ? BYTES_PIPE : left;
                nBytesWrite = write(pipes[1], write_p, once);
                if(nBytesWrite != once) {
                    info(logfds[threadid], "Write %ld/%ld bytes to pipe. ", nBytesWrite, once);
                    if(nBytesWrite == -1) {
                        error(logfds[threadid], "thread %ld failed to write to pipe, errno: %d", threadid, errno);
                        break;
                    }
                }
                left = left - nBytesWrite;
                write_p = write_p + nBytesWrite;
            }
            
            r2p2sstat[threadid].nBytes += reply->len;
            freeReplyObject(reply);
        }
        info(logfds[threadid], "consume_pkt_thread quit.");
        
        close(pipes[1]);
        redisFree(c);
    }
    
    return NULL;
}

void start_r2p2s() {
    get_pcap_file_header(DEFAULT_SNAPLEN, &pfh);
    
    memset(r2p2s_threads, 0, sizeof(r2p2s_threads));
    long i;
    for(i=0; i<num_threads; i++) {
        pthread_create(&r2p2s_threads[i], NULL, consume_pkt_thread, (void*)i);
    }
}

void start_n2r() {
    
    memset(pds, 0, sizeof(pds));

    long i;
    memset(n2r_threads, 0, sizeof(n2r_threads));
    for(i=0; i<num_threads; i++) {
        pthread_create(&n2r_threads[i], NULL, produce_pkt_thread, (void*)i);
    }
}

void stop_n2r() {
    printf("Stopping n2r processes ... ");
    info(logfdm, "stop n2r ...");
    int i;
    for(i=0; i<num_threads; i++) {
        pthread_join(n2r_threads[i], NULL);
    }
    printf("Done\n");
}

void stop_r2p2s() {
    printf("Stopping r2p2s processes ... ");
    info(logfdm, "stop r2p2s ...");
    int i;
    for(i=0; i<num_threads; i++) {
        pthread_join(r2p2s_threads[i], NULL);
    }
    printf("Done\n");
}

void stats_n2r(char *buff) {
    char datastr[256];
    pfring_stat pfstat;

    int i;
    for(i=0; i<num_threads; i++) {
        n2r_stat_t *tp = &n2rstat[i];
        
        memset(&pfstat, 0, sizeof(pfring_stat));
        if(pfring_stats(pds[i], &pfstat) != 0) {
            warn(logfds[i], "failed to get stat from pfring.");
        }
        else {
            tp->ndroped = pfstat.drop;
        }
        
        // amount
        sprintf(datastr, "packets,thread=%d,type=amount,unit=num value=%ld %ld%06ld000\n",
                i, tp->recv_nPkts, nowastat.tv_sec, nowastat.tv_usec);
        strcat(buff, datastr);
        
        sprintf(datastr, "packets,thread=%d,type=amount,unit=bytes value=%ld %ld%06ld000\n",
                i, tp->recv_nBytes, nowastat.tv_sec, nowastat.tv_usec);
        strcat(buff, datastr);
        
        sprintf(datastr, "packets,thread=%d,type=amount,unit=dropn value=%ld %ld%06ld000\n",
                i, tp->ndroped, nowastat.tv_sec, nowastat.tv_usec);
        strcat(buff, datastr);
    }
}

void stats_r2p2s(char *buff) {
    /*
    int i;
    for(i=0; i<num_threads; i++) {
        r2p2s_stat_t *tp = &r2p2sstat[i];
        //printf("thr/core %2d/%2d: handled(bytes): %16ld, cpu: %d\n", i, tp->core, tp->nBytes, tp->cpuusage);
    }
    */
}

void stats_redis(char *buff) {
    char datastr[512];
    
    redisReply *reply;
    
    long i;
    for(i=0; i<num_threads; i++) {
        redisContext *conn = redis_connect(i);
        reply = redisCommand(conn, "llen %ld", i);
        redisstat[i].queuelen = reply->integer;
        freeReplyObject(reply);
        
        sprintf(datastr, "redis,thread=%ld,type=len value=%ld %ld%06ld000\n", i, redisstat[i].queuelen, nowastat.tv_sec, nowastat.tv_usec);
        strcat(buff, datastr);
        
        redisFree(conn);
    }
}

void print_help() {
    printf("Program Help: \n");
    printf("    -r      redis host,             default: %s, this program use redis as intermediate cache tool.\n", host);
    printf("    -p      redis port,             default: %d, default redis port to use.\n", port);
    printf("    -o      output directory,       default: %s, output the tcpflow session files, subdir named threadid will be created.\n", outdir);
    printf("    -t      thread number,          default: %d, each contains 2 workers, capturer and tcpflow worker, bind2core separately.\n", DEFAULT_NUM_THREADS);
    printf("    -i      interface name,         default: %s, the interface will work in promise mode.\n", device);
    printf("    -w      wait time for next pkt, default: %d, means block wait until next pkt arrives (microseconds).\n", waittime);
    printf("    -c      cache size,             default: %d Bytes, means the max data size before writing to redis.\n", DEFAULT_CACHE_SIZE);
    printf("    -d      packet direction,       default: %s, available value: r t rt, means rx_only_direction to capture or so.\n",
           (direction==rx_only_direction) ? "r" : (direction==tx_only_direction) ? "t" : "rt");
    printf("    -v      verbose,                default: %d, 0-quiet, 1-info, 2-warn, 3-error, 4-debug\n", verbose);
    printf("    -x      influxdb conninfo,      default: %s, used for write data to it.\n", influxdb);
    printf("    -u      influxdb username,      default: %s, authorized way is enabled in influxdb configuration.\n", infxuser);
    printf("    -s      influxdb password,      default: %s. username and password should be used together with -x. \n", infxpass);
    printf("    -a      influxdb dbname,        default: %s, the database should be created in advance.\n", dbname);
    printf("    -g      log directory,          default: %s, the directory to output logs, the logs need to rotate by caller if need, especially enabled -v. \n", logdir);
    printf("    -n      time interval,          default: %d, the time interval (seconds) for next statistics.\n", DEFAULT_STAT_INTERVAL);
    printf("    -e      tcpflow executable,     default: %s, the tcpflow executable used to take pcap to session files.\n", bincmd);
    printf("    -z      accepted ports,         default: %s, only the ports in the list would be handled by program. example: '21,25,110,80,8080-8086'\n", acptportstr);
    printf("    -f      filter limit,           default: %d, the rate number of packets to dropped. 0 means no filter; i.e. 20 means 1/5 of packets would be dropped.\n", DEFAULT_FILTER_LIMIT);
    printf("    -j      src address,            default: [all], the src address and netmask to accept/drop, i.e. 'accept 192.168.0.1 255.255.255.0' 'drop 10.0.0.1 255.255.0.0'\n");
    printf("    -k      dst address,            default: [all], the dst address and netmask to accept/drop, i.e. 'accept 192.168.0.1 255.255.255.0' 'drop 10.0.0.1 255.255.0.0'\n");
}

void print_config() {
    int maxline = 32;
    char buff[32][512];
    memset(buff, 0, sizeof(buff));
    
    int j = 0;
    sprintf(buff[j++], "Running Configuration: ");
    sprintf(buff[j++], "==============================================");
    sprintf(buff[j++], "    %-32s : %s", "Redis Host(-r)", host);
    sprintf(buff[j++], "    %-32s : %d", "Redis Port(-p)", port);
    sprintf(buff[j++], "    %-32s : %s", "Output Folder(-o)", outdir);
    sprintf(buff[j++], "    %-32s : %d", "Number of Threads(-t)", num_threads);
    sprintf(buff[j++], "    %-32s : %s", "Interface Name(-i)", device);
    sprintf(buff[j++], "    %-32s : %d", "Waiting Time for Pkts(-w)", waittime);
    sprintf(buff[j++], "    %-32s : %d", "Internal Cache Size(-c)", cache_size);
    sprintf(buff[j++], "    %-32s : %s", "Capturing Direction(-d)", (direction==rx_only_direction) ? "r" : (direction==tx_only_direction) ? "t" : "rt");
    sprintf(buff[j++], "    %-32s : %d", "Verbose Level(-v)", verbose);
    sprintf(buff[j++], "    %-32s : %s", "Influxdb Connection(-x)", influxdb);
    sprintf(buff[j++], "    %-32s : %s", "Influxdb Username(-u)", infxuser);
    sprintf(buff[j++], "    %-32s : %s", "Influxdb Password(-s)", infxpass);
    sprintf(buff[j++], "    %-32s : %s", "Influxdb Database(-a)", dbname);
    sprintf(buff[j++], "    %-32s : %s", "Log Directory(-g)", logdir);
    sprintf(buff[j++], "    %-32s : %d", "Stats Time Interval(-n)", stat_interval);
    sprintf(buff[j++], "    %-32s : %s", "Tcpflow Executable(-e)", bincmd);
    sprintf(buff[j++], "    %-32s : %s", "Accepted Port List(-z)", acptportstr);
    sprintf(buff[j++], "    %-32s : %d", "Filter Limit(-f)", filter_limit);
    sprintf(buff[j++], "    %-32s : %s", "action + src address(-j)", srcaddrs);
    sprintf(buff[j++], "    %-32s : %s", "actuib + dst address(-k)", dstaddrs);
    sprintf(buff[j++], "==============================================");
    
    int i;
    for(i=0; i<maxline && strlen(buff[i]); i++) {
        printf("%s\n", buff[i]);
        info(logfdm, buff[i]);
    }
}

void* stat_pkt_thread(void *args) {
    char buff[65536];
    char cmd[65536];
    while(!stop) {
        memset(buff, 0, sizeof(buff));
        gettimeofday(&nowastat, NULL);
        
        stats_n2r(buff);
        stats_redis(buff);
        stats_r2p2s(buff);
        
        sprintf(cmd, "curl -i -XPOST '%s/write?db=%s&u=%s&p=%s' --data-binary '%s' %s", influxdb, dbname, infxuser, infxpass, buff, curlout);
        int rc = system(cmd);
        // only part of the log to output
        cmd[128] = 0;
        strcpy(cmd+125, "...");
        info(logfdm, "execute command: %s: result: %d", cmd, rc);
        
        int nsec = stat_interval;
        while(nsec > 0) {
            sleep(1);
            nsec --;
        }
    }
    
    return NULL;
}

void start_stat() {
    if(!verbose) { return; }

    memset(&nowastat, 0, sizeof(struct timeval));
    
    pthread_create(&stat_thread, NULL, stat_pkt_thread, NULL);
}

void stop_stat() {
    printf("Stopping stat processes ... ");
    info(logfdm, "stop stating process..");
    pthread_join(stat_thread, NULL);
    printf("Done\n");
}

void print(int level, int fd, char *log) {
    if(verbose >= level) {
        
        char logentry[1024];
        memset(logentry, 0, sizeof(logentry));
        
        char strtime[20];// = {0};
        memset(strtime, 0, sizeof(strtime));
        
        time_t timep;
        //struct tm *p_tm;
        //timep = time(NULL);
        //p_tm = gmtime(&timep);
        //before calling localtime, it needs to set tzname, timezone, and daylight.
        // or there is a strange error happen: subprocess startup fails.
        //p_tm = localtime(&timep);
        //strftime(strtime, sizeof(strtime), "%Y-%m-%d %H:%M:%S", p_tm);
        sprintf(strtime, "%ld", timep);
        char *L = (level == LDEBUG) ? "D" :
                (level == LERROR) ? "E" :
                (level == LWARN) ? "W" :
                (level == LINFO) ? "I" : "U";
        sprintf(logentry, "%s %s: %s\n", L, strtime, log);
        int bwrt = write(fd, logentry, strlen(logentry));
        if(bwrt != strlen(logentry)) {
            // nothing
        }
        if(verbose >= 4) printf("Log: %s", logentry);
    }
}

void info(int fd, char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buff[1024];
    memset(buff, 0, sizeof(buff));
    vsprintf(buff, fmt, args);
    print(LINFO, fd, buff);
    va_end(args);
}

void warn(int fd, char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buff[1024];
    memset(buff, 0, sizeof(buff));
    vsprintf(buff, fmt, args);
    print(LWARN, fd, buff);
    va_end(args);
}

void error(int fd, char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buff[1024];
    memset(buff, 0, sizeof(buff));
    vsprintf(buff, fmt, args);
    print(LERROR, fd, buff);
    va_end(args);
}

void debug(int fd, char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buff[1024];
    memset(buff, 0, sizeof(buff));
    vsprintf(buff, fmt, args);
    print(LDEBUG, fd, buff);
    va_end(args);
}

void start_log() {
    memset(logfds, -1, sizeof(logfds));
    logfdm = -1;
    
    char logpath[256];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    int i;
    for(i=0; i<num_threads; i++) {
        sprintf(logpath, "%s/%ld.%d.log", logdir, tv.tv_sec, i);
        logfds[i] = open(logpath, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if(logfds[i] < 0) {
            printf("failed to open file %s to write logs.\n", logpath);
        }
    }
    
    sprintf(logpath, "%s/%ld.main.log", logdir, tv.tv_sec);
    logfdm = open(logpath, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if(logfdm < 0) {
        printf("failed to open file %s to write logs.\n", logpath);
    }
}

void stop_log() {
    printf("Closing log handlers ... ");
    close(logfdm);
    
    int i;
    for(i=0; i<num_threads; i++) {
        close(logfds[i]);
    }
    printf("Done\n");
}

void parse_ports(char *str) {
    memset(acptport, 0, sizeof(acptport));
    strcpy(acptportstr, str);
    
    char buff[6];
    
    int len = strlen(str);
    int start=0, end;
    int pstart = 0, pend = 0;
    int i = 0;
    while(i < len) {
        char c = str[i];
        if(c >= '0' && c <=9) {}
        if(c == '-') {
            end = i;
            memset(buff, 0, sizeof(buff));
            strncpy(buff, str+start, end-start);
            pstart = atoi(buff);
            start = i + 1;
        }
        if(c == ',' || i == len - 1) {
            end = (i == len - 1) ? len : i;
            memset(buff, 0, sizeof(buff));
            strncpy(buff, str+start, end-start);
            pend = atoi(buff);
            start = i + 1;
            if(pstart) {
                int n;
                for(n=pstart; n<=pend; n++) {
                    acptport[n] = 1;
                }
                pstart = 0;
            }
            else {
                acptport[pend] = 1;
            }
        }

        i ++;
    }
}

void add_srcaddrs_filter(char *str) {
    // accept 192.168.0.1/24
    // drop 10.0.0.1/16
    filtering_rule *fr = &filtering_rule_list[filtering_rule_count];
    char *ipmask = str;
    char *ip = NULL;
    char *mask = NULL;
    if(strncmp("accept", str, strlen("accept")) == 0) {
        fr->rule_action = forward_packet_and_stop_rule_evaluation;
        ipmask = str + strlen("accept ");
    }
    else if(strncmp("drop", str, strlen("drop")) == 0) {
        fr->rule_action = dont_forward_packet_and_stop_rule_evaluation;
        ipmask = str + strlen("drop ");
    }
    
    int i = 0;
    
    while (i < strlen(ipmask)) {
        char c = ipmask[i];
        if (c == ' ') {
            strncpy(ip, ipmask, i);
            strcpy(mask, ipmask + i + 1);
            break;
        }
        i ++;
    }
    
    printf("%s %s\n", ip, mask);
    
}

void add_dstaddrs_filter(char *str) {
}

int main(int argc, char **argv) {
    
    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);
    signal(SIGPIPE, sigpipeproc);
    
    // default setting:
    strcpy(host, "127.0.0.1");
    port = 6379;
    strcpy(outdir, "/tmp");
    num_threads = DEFAULT_NUM_THREADS;
    num_core = sysconf( _SC_NPROCESSORS_ONLN );
    strcpy(device, "eth0");
    direction = rx_only_direction;
    cache_size = DEFAULT_CACHE_SIZE;
    wait_for_packet = 1;
    waittime = 0;
    strcpy(influxdb, "http://localhost:9096");
    strcpy(curlout, "> /dev/null 2>&1");
    strcpy(dbname, "nfr");
    strcpy(infxuser, "writeuser");
    strcpy(infxpass, "DeDGRgE");
    verbose = LERROR;
    strcpy(logdir, "/var/log/nfr");
    stat_interval = DEFAULT_STAT_INTERVAL;
    strcpy(bincmd, "/usr/bin/tcpflow");
    memset(acptport, 1, sizeof(acptport));
    strcpy(acptportstr, "1-65536");
    filter_limit = DEFAULT_FILTER_LIMIT;
    memset(srcaddrs, 0, MAX_ADDR_STRING_LENGTH);
    memset(dstaddrs, 0, MAX_ADDR_STRING_LENGTH);
    filtering_rule_count = 0;
    memset(filtering_rule_list, 0, sizeof(filtering_rule) * MAX_FILTERING_RULE_COUNT);
    
    if(argc > 1) {
        if(strcmp(argv[1], "help") == 0 || strcmp(argv[1], "-h") == 0
           || strcmp(argv[1], "--help") == 0) {
            print_help();
            exit(0);
        }
    }
    
    struct stat buf;
    int cc;
    char opt;
    while((opt = getopt(argc,argv,"r:p:o:t:i:w:c:d:v:x:u:s:a:g:n:e:z:f:j:k:")) != -1) {
        
        switch(opt) {
            case 'r':   // redis host
                strcpy(host, optarg);
                break;
            case 'p':   // redis port
                port = atoi(optarg);
                break;
            case 'o':   // output directory
                cc=stat(optarg,&buf);
                if (cc != 0 || S_ISDIR(buf.st_mode) == 0) {
                    error(logfdm, "Invalid folder: '%s' for output!\n", optarg);
                    exit(1);
                }
                strcpy(outdir, optarg);
                break;
            case 't':
                num_threads = atoi(optarg);
                if(num_threads > MAX_NUM_THREADS || num_threads <= 0) {
                    warn(logfdm, "Set to default thread number: %d\n", DEFAULT_NUM_THREADS);
                    num_threads = DEFAULT_NUM_THREADS;
                }
                break;
            case 'i':
                strcpy(device, optarg);
                break;
            case 'w':
                waittime = atoi(optarg);
                if(waittime<=0) {
                    wait_for_packet = 1;
                    waittime = 0;
                }
                else {
                    wait_for_packet = 0;
                }
                break;
            case 'c':
                cache_size = atoi(optarg);
                if(cache_size > MAX_CACHE_SIZE || cache_size <= MIN_CACHE_SIZE) {
                    warn(logfdm, "Set to default cache size: %d\n", DEFAULT_CACHE_SIZE);
                    cache_size = DEFAULT_CACHE_SIZE;
                }
                break;
            case 'd':
                if(strcmp(optarg, "r") == 0) {
                    direction = rx_only_direction;
                }
                else if(strcmp(optarg, "t") == 0) {
                    direction = tx_only_direction;
                }
                else { // rt
                    direction = rx_and_tx_direction;
                }
                break;
            case 'v':
                verbose = atoi(optarg);
                break;
            case 'x':
                strcpy(influxdb, optarg);
                break;
            case 'u':
                strcpy(infxuser, optarg);
                break;
            case 's':
                strcpy(infxpass, optarg);
                break;
            case 'a':
                strcpy(dbname, optarg);
                break;
            case 'g':
                strcpy(logdir, optarg);
                break;
            case 'n':
                stat_interval = atoi(optarg);
                break;
            case 'e':
                strcpy(bincmd, optarg);
                break;
            case 'z':
                parse_ports(optarg);
                break;
            case 'f':
                filter_limit = atoi(optarg);
            case 'j':
                add_srcaddrs_filter(optarg);
            case 'k':
                add_dstaddrs_filter(optarg);
        }
    }

    //print_config();
    //return 0;
    
    cc=stat(logdir, &buf);
    if(cc != 0 || S_ISDIR(buf.st_mode) == 0) {
        error(logfdm, "Invalid folder: '%s' for log!\n", logdir);
        exit(1);
    }
    if(verbose >= LDEBUG) {
        sprintf(curlout, ">> %s/curl.log 2>&1", logdir);
    }
    
    start_log();
    print_config();
    
    start_r2p2s();
    start_n2r();
    start_stat();
    
    while(!stop) { sleep(1); }

    stop_stat();
    stop_n2r();
    stop_r2p2s();
    stop_log();
    
    return 0;
}
