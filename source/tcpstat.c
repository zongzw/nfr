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
#include <async.h>
#include <adapters/libevent.h>

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
#define DEFAULT_CACHE_SIZE      65536
#define MAX_CACHE_SIZE          1048576
#define MIN_CACHE_SIZE          128
#define BYTES_PIPE              65536
#define	ETHERTYPE_IP            0x0800	/* IP protocol */
#define DEFAULT_STAT_INTERVAL   15

#define LQUIET  0
#define LINFO   1
#define LWARN   2
#define LERROR  3
#define LDEBUG  4

static int stop = 0;

static char outdir[256];
static int num_threads;
static pthread_t A_threads[MAX_NUM_THREADS];
static pthread_t B_thread;
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
static long acptport[65537];
static char acptportstr[512];
static int snaplen = DEFAULT_SNAPLEN;
static u_int32_t flags = 0;

//static char script_syn[128];
//static char script_fin[128];
//static char script_rst[128];
//static char script_nrl[128];

static char *source = "\
redis.replicate_commands() \
local t = redis.call('time')[1] \
\
for i = 1, #KEYS do \
    if(KEYS[i] == 'SYN') then \
        local a = redis.call('hmget', ARGV[i], 'P', 'B') \
        if(a[1] == false) then  \
            local b = redis.call('hget', 'ACK', 'N') \
            redis.call('hset', 'ACK', 'N', b + 1) \
        end \
        redis.call('hmset', ARGV[i], 'P', 0, 'B', 0, 'S', t, 'E', t) \
\
    elseif(KEYS[i] == 'RST' or KEYS[i] == 'FIN') then  \
        local a = redis.call('hmget', ARGV[i], 'P', 'B', 'S') \
        if(a[1]) then \
            local b \
            local d = t - a[3] \
\
            b = redis.call('hmget', KEYS[i], 'N', 'P', 'B', 'D') \
            redis.call('hmset', KEYS[i], 'N', b[1] + 1, 'P', b[2] + a[1], 'B', b[3] + a[2], 'D', b[4] + d) \
             \
            b = redis.call('hmget', 'ACK', 'N', 'P', 'B') \
            redis.call('hmset', 'ACK', 'N', b[1] - 1, 'P', b[2] - a[1], 'B', b[3] - a[2]) \
\
            redis.call('del', ARGV[i]) \
        end \
    else \
        local a = redis.call('hmget', ARGV[i], 'P', 'B') \
        if(a[1]) then  \
            redis.call('hmset', ARGV[i], 'P', a[1] + 1, 'B', KEYS[i] + a[2], 'E', t) \
            local b = redis.call('hmget', 'ACK', 'P', 'B') \
            redis.call('hmset', 'ACK', 'P', b[1] + 1, 'B', b[2] + KEYS[i]) \
        end \
    end \
end \
";

static char script[128];


/*
 50 #define REDIS_REPLY_STRING 1
 51 #define REDIS_REPLY_ARRAY 2
 52 #define REDIS_REPLY_INTEGER 3
 53 #define REDIS_REPLY_NIL 4
 54 #define REDIS_REPLY_STATUS 5
 55 #define REDIS_REPLY_ERROR 6
 */

 // 111 /* This is the reply object returned by redisCommand() */
 // 112 typedef struct redisReply {
 // 113     int type; /* REDIS_REPLY_* */
 // 114     long long integer; /* The integer when type is REDIS_REPLY_INTEGER */
 // 115     size_t len; /* Length of string */
 // 116     char *str; /* Used for both REDIS_REPLY_ERROR and REDIS_REPLY_STRING */
 // 117     size_t elements; /* number of elements, for REDIS_REPLY_ARRAY */
 // 118     struct redisReply **element; /* elements vector for REDIS_REPLY_ARRAY */
 // 119 } redisReply;

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


redisAsyncContext* redis_async_connect(){
    
    redisAsyncContext *c = redisAsyncConnect(host, port);
    if (c == NULL || c->err) {
        /* Let *c leak for now... */
        printf("Error: %s\n", c->errstr);
        error(logfdm, "error connecting redis.");
        redisAsyncDisconnect(c);
        exit(1);
    }
    
    return c;
}

redisContext* redis_connect(){
    
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    redisContext *c = redisConnectWithTimeout(host, port, timeout);
    if (c == NULL || c->err) {
        if (c) {
            error(logfdm, "Redis Connection error: %s", c->errstr);
            redisFree(c);
        } else {
            error(logfdm, "Connection error: can't allocate redis context.");
        }
        exit(1);
    }
    
    return c;
}

void connectCallback(const redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        printf("Error: %s\n", c->errstr);
        stop = 1;
        
        error(logfdm, "failed to connect redis");
        return;
    }
    //printf("Connected...\n");
    info(logfdm, "Redis Connected...");
}

void disconnectCallback(const redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        printf("Error: %s\n", c->errstr);
        return;
    }
    printf("Disconnected...\n");
}

void getCallback(redisAsyncContext *c, void *r, void *privdata) {
    redisReply *reply = r;
    if (reply == NULL) return;
    printf("return: %s\n", reply->str);
}

int should_drop(struct pkt_parsing_info *pktparsed) {
    if(pktparsed->eth_type != ETHERTYPE_IP || pktparsed->l3_proto != 6) return 1;
    if(acptport[pktparsed->l4_src_port] == 0 && acptport[pktparsed->l4_dst_port] == 0) return 1;
    
    if(acptport[pktparsed->l4_src_port]) acptport[pktparsed->l4_src_port] ++;
    if(acptport[pktparsed->l4_dst_port]) acptport[pktparsed->l4_dst_port] ++;
    
    return 0;
}

void* C_function(void *args) {
    pthread_detach(pthread_self());
    
    struct event_base *base = event_base_new();
    
    redisAsyncContext *c = args;
    redisLibeventAttach(c, base);
    redisAsyncSetConnectCallback(c, connectCallback);
    redisAsyncSetDisconnectCallback(c, disconnectCallback);
    event_base_dispatch(base);
    
    return NULL;
}

void exec_redis_cmd(redisAsyncContext *conn, char *cmdcache, int cmdlen, char *keys, char *argk) {
    
    sprintf(cmdcache, "EVALSHA %s %d %s %s", script, cmdlen, keys, argk);
    //printf("%s\n", cmdcache);
    redisAsyncCommand(conn, NULL, NULL, cmdcache);
    
    // !!!!!!!!!!! redis keng die!
    // terrible implementation of hiredis/redis.c:redisvFormatCommand !!!!
    // 210 int redisvFormatCommand(char **target, const char *format, va_list ap) {
    //reply = redisCommand(conn, "EVALSHA %s %d %s %s", script, cmdlen, keys, argk);
    
    // synchronized mode
    //redisReply *reply;
    //reply = redisCommand(conn, cmdcache);
    //freeReplyObject(reply);

}

void* A_function(void *args) {

    long threadid = (long) args;
    
    int core_id = threadid % num_core;
    if(bind2core(core_id) == 0) {
        info(logfds[threadid], "Set A on core %d/%d", core_id, num_core);
    }
    
    redisAsyncContext *conn = redis_async_connect();
    //redisContext *conn = redis_connect();
    //redisReply *reply;
    pthread_t C_thread;
    pthread_create(&C_thread, NULL, C_function, (void*)conn);
    
    u_char buffer[MAX_PKT_SIZE];
    u_char *buffer_p = buffer;
    
    char cmdcache[cache_size];
    int argklen = 8+1+5+1+8+1+5+1; // aabbccdd:ppppp-eeffgghh:ppppp
    int keylen = strlen("65536 "); // SYN | RST |FIN |5-bit-num
    int cmdsize = (cache_size - strlen("EVALSHA ") - 65 /* LEN of sha1 */) / (keylen + argklen);
    char keys[cmdsize * keylen + 1];
    char argk[cmdsize * argklen + 1];
    
    memset(keys, 0, sizeof(keys));
    memset(argk, 0, sizeof(argk));
    memset(cmdcache, 0, sizeof(cmdcache));
    
    int cmdlen = 0;
    
    struct pfring_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    
    pfring  *pd_in_thr;
    int rc;
    
    pd_in_thr = pfring_open(device, snaplen, flags);
    if(pd_in_thr == NULL) {
        error(logfds[threadid], "pfring_open error [%s] (pf_ring not loaded or interface %s is down ?)", strerror(errno), device);
        return NULL;
    }
    pds[threadid] = pd_in_thr;
    
    //rc = pfring_set_cluster(pd_in_thr, 1, cluster_per_flow_tcp_5_tuple);
    rc = pfring_set_cluster(pd_in_thr, 2, cluster_per_flow);
    info(logfds[threadid], "pfring_set_cluster returned %d", rc);
    
    if((rc = pfring_set_direction(pd_in_thr, direction)) != 0){
        error(logfds[threadid], "failed to set direction recv only.");
    }
    
    if (pfring_enable_ring(pd_in_thr) != 0) {
        error(logfds[threadid], "Unable to enable ring :-(");
        pfring_close(pd_in_thr);
        return NULL;
    }
    
    struct timeval nowtime, lasttime;
    
    gettimeofday(&nowtime, NULL);
    gettimeofday(&lasttime, NULL);
    //memset(&lasttime, 0, sizeof(struct timeval));
    
    char src[64], dst[64], tuple4[128];
    char lenstr[8];
    
    while(!stop) {
        
        gettimeofday(&nowtime, NULL);
        
        //if((rc = pfring_recv(pd_in_thr, &buffer_p, MAX_PKT_SIZE, &hdr, wait_for_packet)) > 0) {
        memset(&hdr, 0, sizeof(hdr));
        if((rc = pfring_recv_parsed(pd_in_thr, &buffer_p, MAX_PKT_SIZE, &hdr, wait_for_packet, 4, 0, 0)) > 0) {
            
            struct pkt_parsing_info *pktparsed = &(hdr.extended_hdr.parsed_pkt);
            //printf("new pkt: src: %x, dst: %x, sport: %d, dport: %d, proto: %d\n", pktparsed->ip_src.v4, pktparsed->ip_dst.v4, pktparsed->l4_src_port, pktparsed->l4_dst_port, pktparsed->l3_proto);
            if(!should_drop(pktparsed)) {
                sprintf(src, "%08x:%05d", pktparsed->ip_src.v4, pktparsed->l4_src_port);
                sprintf(dst, "%08x:%05d", pktparsed->ip_dst.v4, pktparsed->l4_dst_port);
                if(strcmp(src, dst) > 0) {
                    sprintf(tuple4, "%s-%s", src, dst);
                }
                else {
                    sprintf(tuple4, "%s-%s", dst, src);
                }
                
                if((pktparsed->tcp.flags & 0x02) != 0) { // syn
                    strcat(keys, "SYN ");
                    strcat(argk, tuple4); strcat(argk, " ");
                }
                else if((pktparsed->tcp.flags & 0x04) != 0) { // rst
                    strcat(keys, "RST ");
                    strcat(argk, tuple4); strcat(argk, " ");
                }
                else if((pktparsed->tcp.flags & 0x01) != 0) { // fin
                    strcat(keys, "FIN ");
                    strcat(argk, tuple4); strcat(argk, " ");
                }
                else { // nrl
                    sprintf(lenstr, "%d ", hdr.len);
                    strcat(keys, lenstr);
                    strcat(argk, tuple4); strcat(argk, " ");
                }
                
                cmdlen ++;
                if(cmdlen >= cmdsize) {
                    exec_redis_cmd(conn, cmdcache, cmdlen, keys, argk);
                    
                    memset(keys, 0, sizeof(keys));
                    memset(argk, 0, sizeof(argk));
                    memset(cmdcache, 0, sizeof(cmdcache));
                    cmdlen = 0;
                    gettimeofday(&lasttime, NULL);
                }
            }
            
        }
        else {
            if(wait_for_packet == 0) usleep(waittime);//sched_yield();
        }
        
        if((nowtime.tv_sec - lasttime.tv_sec) > 1 && cmdlen > 0) {
            exec_redis_cmd(conn, cmdcache, cmdlen, keys, argk);
            
            memset(keys, 0, sizeof(keys));
            memset(argk, 0, sizeof(argk));
            memset(cmdcache, 0, sizeof(cmdcache));
            cmdlen = 0;
            gettimeofday(&lasttime, NULL);
        }
        
        
    }
    
    printf("%ld: A function quit \n", threadid);
    info(logfds[threadid], "A quit.");
    redisAsyncDisconnect(conn);
    //redisFree(conn);
    pfring_close(pd_in_thr);
    pds[threadid] = 0;
    //pthread_join(C_thread, NULL);
    return NULL;
}

void start_A() {
    
    redisContext *conn = redis_connect();
    redisReply *reply;
    
    reply = redisCommand(conn, "SCRIPT LOAD %s", source);
    strcpy(script, reply->str);
    freeReplyObject(reply);
    
    reply = redisCommand(conn, "hmset FIN N 0 P 0 B 0 D 0");
    freeReplyObject(reply);
    
    reply = redisCommand(conn, "hmset RST N 0 P 0 B 0 D 0");
    freeReplyObject(reply);
    
    reply = redisCommand(conn, "hmset ACK N 0 P 0 B 0");
    freeReplyObject(reply);
    
    redisFree(conn);

    memset(pds, 0, sizeof(pds));
    
    long i;
    memset(A_threads, 0, sizeof(A_threads));
    for(i=0; i<num_threads; i++) {
        pthread_create(&A_threads[i], NULL, A_function, (void*)i);
    }
}

void stop_A() {
    printf("Stopping A processes ... ");
    info(logfdm, "stop A ...");
    int i;
    for(i=0; i<num_threads; i++) {
        pthread_join(A_threads[i], NULL);
    }
    printf("Done\n");
}

void* B_function(void *args) {
    char buff[65536];
    memset(buff, 0, sizeof(buff));
    char datastr[512];
    
    redisContext *conn = redis_connect();
    redisReply *reply;
    
    int times = 10;
    while(!stop && times > 0) {
        times --;
        reply = redisCommand(conn, "exists ACK RST FIN");
        if(reply->integer == 3) {
            break;
        }
        else sleep(1);
    }
    if(times == 0) {
        printf("not exists in redis: ACK RST FIN\n");
        error(logfdm, "not exists in redis: ACK RST FIN");
        exit(1);
    }
    
    struct timeval nowtime;
    pfring_stat pfstat;
    long pkt_recv, pkt_drop;
    
    while(!stop) {
        
        memset(buff, 0, sizeof(buff));
        gettimeofday(&nowtime, NULL);
        
        pkt_recv = pkt_drop = 0;
        for(int i=0; i<num_threads; i++) {
            memset(&pfstat, 0, sizeof(pfring_stat));
            if(pfring_stats(pds[i], &pfstat) != 0) {
                warn(logfds[i], "failed to get stat from pfring.");
            }
            else {
                pkt_recv += pfstat.recv;
                pkt_drop += pfstat.drop;
            }
        }
        
        sprintf(datastr, "tcpstat,type=pkt_recv,unit=n value=%ld %ld%06ld000\n", pkt_recv, nowtime.tv_sec, nowtime.tv_usec);
        strcat(buff, datastr);
        sprintf(datastr, "tcpstat,type=pkt_drop,unit=n value=%ld %ld%06ld000\n", pkt_drop, nowtime.tv_sec, nowtime.tv_usec);
        strcat(buff, datastr);
        
        reply = redisCommand(conn, "hmget ACK N P B");
        sprintf(datastr, "tcpstat,type=ack,unit=n value=%s %ld%06ld000\n", reply->element[0]->str, nowtime.tv_sec, nowtime.tv_usec);
        strcat(buff, datastr);
        sprintf(datastr, "tcpstat,type=ack,unit=p value=%s %ld%06ld000\n", reply->element[1]->str, nowtime.tv_sec, nowtime.tv_usec);
        strcat(buff, datastr);
        sprintf(datastr, "tcpstat,type=ack,unit=b value=%s %ld%06ld000\n", reply->element[2]->str, nowtime.tv_sec, nowtime.tv_usec);
        strcat(buff, datastr);
        freeReplyObject(reply);
        
        reply = redisCommand(conn, "hmget RST N P B D");
        sprintf(datastr, "tcpstat,type=rst,unit=n value=%s %ld%06ld000\n", reply->element[0]->str, nowtime.tv_sec, nowtime.tv_usec);
        strcat(buff, datastr);
        sprintf(datastr, "tcpstat,type=rst,unit=p value=%s %ld%06ld000\n", reply->element[1]->str, nowtime.tv_sec, nowtime.tv_usec);
        strcat(buff, datastr);
        sprintf(datastr, "tcpstat,type=rst,unit=b value=%s %ld%06ld000\n", reply->element[2]->str, nowtime.tv_sec, nowtime.tv_usec);
        strcat(buff, datastr);
        sprintf(datastr, "tcpstat,type=rst,unit=d value=%s %ld%06ld000\n", reply->element[3]->str, nowtime.tv_sec, nowtime.tv_usec);
        strcat(buff, datastr);
        freeReplyObject(reply);
        
        
        reply = redisCommand(conn, "hmget FIN N P B D");
        sprintf(datastr, "tcpstat,type=fin,unit=n value=%s %ld%06ld000\n", reply->element[0]->str, nowtime.tv_sec, nowtime.tv_usec);
        strcat(buff, datastr);
        sprintf(datastr, "tcpstat,type=fin,unit=p value=%s %ld%06ld000\n", reply->element[1]->str, nowtime.tv_sec, nowtime.tv_usec);
        strcat(buff, datastr);
        sprintf(datastr, "tcpstat,type=fin,unit=b value=%s %ld%06ld000\n", reply->element[2]->str, nowtime.tv_sec, nowtime.tv_usec);
        strcat(buff, datastr);
        sprintf(datastr, "tcpstat,type=fin,unit=d value=%s %ld%06ld000\n", reply->element[3]->str, nowtime.tv_sec, nowtime.tv_usec);
        strcat(buff, datastr);
        freeReplyObject(reply);
        
        char cmd[8096];
        sprintf(cmd, "curl -i -XPOST '%s/write?db=%s&u=%s&p=%s' --data-binary '%s' %s", influxdb, dbname, infxuser, infxpass, buff, curlout);
        int rc = system(cmd);
        // only part of the log to output
        cmd[128] = 0;
        strcpy(cmd+125, "...");
        info(logfdm, "execute command: %s: result: %d", cmd, rc);
        
        int nsec = stat_interval;
        while(!stop && nsec > 0) {
            sleep(1);
            nsec --;
        }
    }
    redisFree(conn);
    return NULL;
}

void start_B() {
    if(!verbose) { return; }

    pthread_create(&B_thread, NULL, B_function, NULL);
}

void stop_B() {
    printf("Stopping B processes ... ");
    info(logfdm, "stop B process..");
    pthread_join(B_thread, NULL);
    printf("Done\n");
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
    //printf("    -e      tcpflow executable,     default: %s, the tcpflow executable used to take pcap to session files.\n", bincmd);
    printf("    -z      accepted ports,         default: %s, only the ports in the list would be handled by program. example: '21,25,110,80,8080-8086'\n", acptportstr);
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
    //sprintf(buff[j++], "    %-32s : %s", "Output Folder(-o)", outdir);
    sprintf(buff[j++], "    %-32s : %d", "Number of Threads(-t)", num_threads);
    sprintf(buff[j++], "    %-32s : %s", "Interface Name(-i)", device);
    sprintf(buff[j++], "    %-32s : %d", "Waiting Time for Pkts(-w)", waittime);
    sprintf(buff[j++], "    %-32s : %d", "Internal Cache Size(-c)", cache_size);
    //sprintf(buff[j++], "    %-32s : %s", "Capturing Direction(-d)", (direction==rx_only_direction) ? "r" : (direction==tx_only_direction) ? "t" : "rt");
    sprintf(buff[j++], "    %-32s : %d", "Verbose Level(-v)", verbose);
    sprintf(buff[j++], "    %-32s : %s", "Influxdb Connection(-x)", influxdb);
    sprintf(buff[j++], "    %-32s : %s", "Influxdb Username(-u)", infxuser);
    sprintf(buff[j++], "    %-32s : %s", "Influxdb Password(-s)", infxpass);
    sprintf(buff[j++], "    %-32s : %s", "Influxdb Database(-a)", dbname);
    sprintf(buff[j++], "    %-32s : %s", "Log Directory(-g)", logdir);
    sprintf(buff[j++], "    %-32s : %d", "Stats Time Interval(-n)", stat_interval);
    //sprintf(buff[j++], "    %-32s : %s", "Tcpflow Executable(-e)", bincmd);
    sprintf(buff[j++], "    %-32s : %s", "Accepted Port List(-z)", acptportstr);
    sprintf(buff[j++], "==============================================");

    int i;
    for(i=0; i<maxline && strlen(buff[i]); i++) {
        printf("%s\n", buff[i]);
        info(logfdm, buff[i]);
    }
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

int main(int argc, char **argv) {
    
    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);
    signal(SIGPIPE, sigpipeproc);
    
    // default setting:
    strcpy(host, "127.0.0.1");
    port = 9379;
    strcpy(outdir, "/tmp");
    num_threads = DEFAULT_NUM_THREADS;
    num_core = sysconf( _SC_NPROCESSORS_ONLN );
    strcpy(device, "eth0");
    direction = rx_and_tx_direction;
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
    
    snaplen = DEFAULT_SNAPLEN;
    flags |= PF_RING_PROMISC;
    
    int stopafter = 0;
    if(argc > 1) {
        if(strcmp(argv[1], "help") == 0 || strcmp(argv[1], "-h") == 0
           || strcmp(argv[1], "--help") == 0) {
            print_help();
            exit(0);
        }
        if(strcmp(argv[1], "test") == 0) {
            stopafter = atoi(argv[2]);
            wait_for_packet = 0;
            waittime = 500;
        }
    }
    
    struct stat buf;
    int cc;
    char opt;
    while((opt = getopt(argc,argv,"r:p:o:t:i:w:c:d:v:x:u:s:a:g:n:e:z:")) != -1) {
        
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
        }
    }

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
    
    start_A();
    start_B();
    
    while(!stop) {
        sleep(1);
        stopafter --;
        if(stopafter == 0) {
            printf("test over.\n");
            stop = 1;
            break;
        }
    }

    printf("stopping process ...\n");
    stop_B();
    stop_A();
    stop_log();
    
    return 0;
}
