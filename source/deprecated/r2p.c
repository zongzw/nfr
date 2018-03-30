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
/*
 * Usage:
 *     ./r2p [redishost [redisport]]
 */

#define THRPOOLSIZE 128

static char host[256];
static int port;
static pthread_t thrpool[THRPOOLSIZE];
static int thrused[THRPOOLSIZE];
//static pthread_mutex_t lock;
static char pcap_folder[256];
static char pcap_file_header[32];
static int toquit = 0;

extern char *optarg;
extern int optind, opterr, optopt;

void print_0x(char *p, int len) {
    int i;

    for(i = 0; i < len; i++)
        printf("%02X ", p[i] & 255);
    printf("\n");
}

int find_avail_thread_index() {
    int i;
    for(i=0; i<THRPOOLSIZE && thrused[i]; i++) {
    }
    if(i != THRPOOLSIZE) return i;
    return i;
}

/*
void* find_keys(void *args) {
    
    char ippair[32];
    
    redisReply *reply;
    reply = redisCommand(c, "keys pcap-data-*:*");
    
    for(size_t i=0; i<reply->elements; i++) {
        char *key = reply->element[i]->str;
        
        redisReply *lenReply = redisCommand(c, "llen %s", key);
        int len = lenReply->integer;
        freeReplyObject(lenReply);
        
        memset(ippair, 0, sizeof(ippair));
        sscanf(key, "pcap-data-%s", ippair);
        
        redisReply *keyreply;
        keyreply = redisCommand(c, "hexists pcap-meta-%s", ippair);
        
        if(keyreply->integer == 0) {
            freeReplyObject(redisCommand(c, "hset pcap-meta-%s state new", ippair));
        }
        freeReplyObject(redisCommand(c, "hset pcap-meta-%s curlen %d", ippair, len));
        freeReplyObject(keyreply);
    }
    
    freeReplyObject(reply);
    return NULL;
}
*/

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

typedef struct {
    int tindex;
    char str[256];
} thread_args_t;

void* handle_key(void *args) {
    redisContext *c = get_redis_connection();
    
    thread_args_t arg;
    memcpy(&arg, (thread_args_t*)args, sizeof(thread_args_t));
    
    char *key = arg.str;
    int tindex = arg.tindex;
    
    char path[256];
    char ippair[64];
    int s, e;
    sscanf(key, "pcap-handled-%d-pcap-handling-%d-pcap-data-%s", &e, &s, ippair);
    snprintf(path, sizeof(path), "%s/pcap-file-%s.pcap", pcap_folder, ippair);
    //printf("handling key name: %s, file: %s\n", key, path);
    
    FILE *fp;
    int append = 0;
    if(access(path, 0) == 0) {
        fp = fopen(path, "a+");
        append = 1;
    }
    else {
        fp = fopen(path, "w");
        fwrite(pcap_file_header, 24, 1, fp);
        fflush(fp);
        append = 0;
    }
    
    // rpop each item to file
    redisReply *itemReply;
    int count = 0;
    while(1) {
        itemReply = redisCommand(c, "rpop %s", key);
        if(itemReply->type == REDIS_REPLY_NIL) break;
        
        count ++;
        fwrite(itemReply->str, itemReply->len, 1, fp);
        fflush(fp);
        freeReplyObject(itemReply);
    }
    // set state to "handled" when finished.
    freeReplyObject(redisCommand(c, "del %s", key));
    redisFree(c);
    
    printf("handled key name: %s, %d packets, file(%s): %s\n", key, count, path, append ? "append":"new");
    // set thread index to be available for next use.
    thrused[tindex] = 0;
    fclose(fp);
    
    return NULL;
}

/*
void* collect_keys(void *args) {
    redisReply *reply;
    
    while(1) {
        reply = redisCommand(c, "keys pcap-meta-*");
        
        // foreach check curlen > 0 && state != "handling"
        for(size_t i=0; i<reply->elements; i++) {
            
            redisReply *lenReply;
            lenReply = redisCommand(c, "hget %s curlen", reply->element[i]->str);
            int len = lenReply->integer;
            freeReplyObject(lenReply);
            
            redisReply *stateReply;
            stateReply = redisCommand(c, "hget %s state", reply->element[i]->str);
            char *state = stateReply->str;
            freeReplyObject(stateReply);
            
            if(strcmp("handling", state) != 0 && len > 0) {
                
                int threadindex = find_avail_thread_index();
                if(threadindex != -1) {
                    thrused[threadindex] = 1;
                    thread_args_t args;
                    args.tindex = threadindex;
                    strcpy(args.str, reply->element[i]->str);
                    
                    //  set state to handling
                    freeReplyObject(redisCommand(c, "hset %s state handling", reply->element[i]->str));
                    
                    pthread_create(&thrpool[threadindex], NULL, handle_keys, &args);
                }
                else break;
            }
        }
        freeReplyObject(reply);
        
        usleep(1000000);
    }
    
    return NULL;
}
*/

void* collect_keys(void *args) {
    printf("start daemon for collecting keys ...\n");
    
    while(!toquit) {
        
        redisReply *reply;
        redisContext *c = get_redis_connection();
        reply = redisCommand(c, "keys pcap-data-*");
        
        struct timeval tv;
        gettimeofday(&tv, NULL);
        
        printf("%lu.%lu: collected %lu keys.\n", tv.tv_sec, tv.tv_usec, reply->elements);
        // foreach check curlen > 0 && state != "handling"
        for(size_t i=0; i<reply->elements; i++) {
            
            char newkey[256];
            snprintf(newkey, sizeof(newkey), "pcap-handling-%lu-%s", tv.tv_sec, reply->element[i]->str);
            
            printf("key: %s, renamed: %s\n", reply->element[i]->str, newkey);
            
            //  set state to handling
            freeReplyObject(redisCommand(c, "rename %s %s", reply->element[i]->str, newkey));
            
            //pthread_create(&thrpool[threadindex], NULL, handle_keys, &args);
            //handle_keys(&args);
        }
        
        freeReplyObject(reply);
        redisFree(c);
        sleep(1);
    }
    
    return NULL;
}

void handle_keys() {
    printf("start daemon for handling keys ...\n");
    
    while(!toquit) {
        
        redisReply *reply;
        redisContext *c = get_redis_connection();
        reply = redisCommand(c, "keys pcap-handling-*");
        
        struct timeval tv;
        gettimeofday(&tv, NULL);
        
        printf("%lu.%lu: handling %lu keys.\n", tv.tv_sec, tv.tv_usec, reply->elements);
        // foreach check curlen > 0 && state != "handling"
        for(size_t i=0; i<reply->elements; i++) {
            int threadindex = find_avail_thread_index();
            if(threadindex == -1) {
                printf("No available thread found.\n");
                break;
            }
            
            char newkey[256];
            snprintf(newkey, sizeof(newkey), "pcap-handled-%lu-%s", tv.tv_sec, reply->element[i]->str);
            
            printf("key: %s, renamed: %s\n", reply->element[i]->str, newkey);
            
            //  set state to handling
            freeReplyObject(redisCommand(c, "rename %s %s", reply->element[i]->str, newkey));
            
            thrused[threadindex] = 1;
            thread_args_t args;
            args.tindex = threadindex;
            strcpy(args.str, newkey);
            
            pthread_create(&thrpool[threadindex], NULL, handle_key, &args);
            //handle_key(&args);
        }
        
        freeReplyObject(reply);
        redisFree(c);
        sleep(1);
        
    }
}

void sigproc(int sig){
    printf("leaving ...\n");
    toquit = 1;
}

int main(int argc, char **argv) {
    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);
    
    strcpy(host, "127.0.0.1");
    port = 6379;
    strcpy(pcap_folder, ".");
    
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
                strcpy(pcap_folder, optarg);
                break;
        }
    }

    memset(thrused, 0, sizeof(thrused));
    
    redisContext *c = get_redis_connection();
    redisReply *headerReply;
    headerReply = redisCommand(c, "get pcap-file-header");
    memset(pcap_file_header, 0, sizeof(pcap_file_header));
    memcpy(pcap_file_header, headerReply->str, headerReply->len);
    freeReplyObject(headerReply);
    redisFree(c);
    
    /*
     * for test

    thread_args_t arg;
    arg.tindex = 0;
    strcpy(arg.str, "pcap-handling-232423-pcap-data-1.1.1.1-3.3.3.3");
    handle_keys(&arg);
    return 0;
     */
    
    
    pthread_t tcollectkeys;
    pthread_create(&tcollectkeys, NULL, collect_keys, NULL);
    //pthread_join(tcollectkeys, NULL);
    
    handle_keys();
    /*
    FILE *fp;
    fp = fopen("/tmp/pcap_file.pcap", "w");
    
    redisReply *reply;
    reply = redisCommand(c, "get pcap-file-header");
    //fwrite(reply->str, 1, sizeof(struct pcap_file_header), fp);
    fwrite(reply->str, 1, reply->len, fp);
    print_0x(reply->str, reply->len);
    freeReplyObject(reply);

    reply = redisCommand(c, "lrange pcap_file 0 -1");
    for (int i = reply->elements; i > 0; i--) {
        fwrite(reply->element[i-1]->str, 1, reply->element[i-1]->len, fp);
        print_0x(reply->element[i-1]->str, reply->element[i-1]->len);
    }
    freeReplyObject(reply);
    */
    
    /* Disconnects and frees the context */

    return 0;
}
