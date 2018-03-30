#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis.h>
#include <pthread.h>
#include <signal.h>
#include <getopt.h>
//#include <io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <pcap/pcap.h>
/*
 * Usage:
 *     ./r2p [redishost [redisport]]
 */

static char host[256];
static int port;
//static char pcap_file_header[32];
static struct pcap_file_header pfh;
static int toquit = 0;
static char outdir[256];

#define NUM_THREADS     4

extern char *optarg;
extern int optind, opterr, optopt;

void print_0x(char *p, int len) {
    int i;

    for(i = 0; i < len; i++)
        printf("%02X ", p[i] & 255);
    printf("\n");
}

redisContext* get_redis_connection(){
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    redisContext *c = redisConnectWithTimeout(host, port, timeout);
    if (c == NULL || c->err) {
        if (c) {
            printf("Connection error: %s\n", c->errstr);
            redisFree(c);
        } else {
            printf("Connection error: can't allocate redis context\n");
        }
        exit(1);
    }
    return c;
}

void sigproc(int sig){
    printf("leaving ...\n");
    toquit = 1;
}

void* consume_pkt_thread(void* args) {
    long threadid = (long)args;
    
    redisContext *c = get_redis_connection();
    redisReply *reply;
    
    int pipes[2];
    int rc = pipe(pipes);
    if(rc == -1) {
        printf("failed to create pipe in thread %ld\n", threadid);
        return NULL;
    }
    
    pid_t pid;
    pid = fork();
    if(pid < 0) {
        printf("thread %ld runs failed: cannot fork sub process for tcpflow.\n", threadid);
        return NULL;
    }
    
    if(pid == 0) {
        printf("start reading from pipes in thread %ld, as child.\n", threadid);
        close(pipes[1]);
        dup2(pipes[0], 0);
        char tcpflowcmd[256];
        sprintf(tcpflowcmd, "tcpflow -r - -o %s", outdir);
        rc = system(tcpflowcmd);
        if(rc == 127 || rc <= 0) {
            printf("error while executing tcpflow command in thread %ld.\n", threadid);
        }
        close(pipes[0]);
    }
    else {
        printf("start reading redis for pkts in thread %ld, as parent.\n", threadid);
        close(pipes[0]);
        //dup2(pipes[1], 1);
        //FILE *fp = fopen("/tmp/testpcap/a.pcap", "w");
        write(pipes[1], &pfh, sizeof(struct pcap_file_header));
        //fwrite(&pfh, sizeof(struct pcap_file_header));
        while(!toquit) {
            reply = redisCommand(c, "rpop %d", threadid);
            if(reply->type == REDIS_REPLY_NIL) {
                sleep(1);
                continue;
            }
            printf("thread %ld: write: %ld\n", threadid, reply->len);
            write(pipes[1], reply->str, reply->len);
            freeReplyObject(reply);
        }
        
        //fclose(fp);
        close(pipes[1]);
    }
    
    redisFree(c);
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);
    
    strcpy(host, "127.0.0.1");
    port = 6379;
    strcpy(outdir, "/tmp/testpcap");
    
    struct stat buf;
    int cc;
    char opt;
    while((opt = getopt(argc,argv,"h:p:o:")) != -1) {
        
        switch(opt) {
            case 'h': // redis host
                strcpy(host, optarg);
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'o':
                cc=stat(optarg,&buf);
                if (cc != 0 || S_ISDIR(buf.st_mode) == 0) {
                    printf("the folder '%s' is invalid!\n", optarg);
                    exit(1);
                }
                strcpy(outdir, optarg);
                break;
        }
    }

    redisContext *c = get_redis_connection();
    redisReply *pfhReply;
    while(1) {
        pfhReply = redisCommand(c, "get pcap-file-header");
        if(pfhReply->type == REDIS_REPLY_NIL) {
            freeReplyObject(pfhReply);
            sleep(1);
        }
        else {
            memset(&pfh, 0, sizeof(struct pcap_file_header));
            memcpy(&pfh, pfhReply->str, pfhReply->len);
            freeReplyObject(pfhReply);
            break;
        }
    }
    
    redisFree(c);
    
    long i;
    pthread_t threads[NUM_THREADS];
    for(i=0; i<NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, consume_pkt_thread, (void*)i);
    }
    
    for(i=0; i<NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    
    /* Disconnects and frees the context */

    return 0;
}
