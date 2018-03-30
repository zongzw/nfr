#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <hiredis.h>
#include <openssl/md5.h> //gcc -lcrypto

// ./redis_perf 1024 10 4 1
// 1024: items, total data size is 1024 * 16
// 10: bucket size(also cosumer size)
// 4: producer size
// 1: consuming method: 
//      1. rpop 
//      2. lindex 1 per time and del all
//      3. lindex 1024 per time and del all

char *host = "127.0.0.1";
int port = 6379;

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

void* cusume_1(void *args){
    redisContext *c = get_redis_connection();

    int bucket_index = (int)args;
    redisReply *reply;
    while(1) {
        reply = redisCommand(c, "rpop %d", bucket_index);
        if(reply->type == REDIS_REPLY_NIL) {
            freeReplyObject(reply);
            break;
        }

        freeReplyObject(reply);
    }

    freeReplyObject(redisCommand(c, "del %d", bucket_index));
    redisFree(c);

    return NULL;
}

void* cusume_2(void *args){
    redisContext *c = get_redis_connection();

    int bucket_index = (int)args;
    redisReply *reply;
    reply = redisCommand(c, "llen %d", bucket_index);
    int len = reply->integer;
    freeReplyObject(reply);

    while(len > 0) {
        len --;
        reply = redisCommand(c, "lindex %d %d", bucket_index, len);
        freeReplyObject(reply);
    }

    freeReplyObject(redisCommand(c, "del %d", bucket_index));
    redisFree(c);

    return NULL;
}


void* cusume_3(void *args){
    redisContext *c = get_redis_connection();

    int bucket_index = (int)args;
    redisReply *reply;
    reply = redisCommand(c, "llen %d", bucket_index);
    int len = reply->integer;
    freeReplyObject(reply);

    int end = -1, start = end + 1;
    while(start < len) {
        end = start + 1024;
        reply = redisCommand(c, "lrange %d %d %d", bucket_index, start, end);
        start = end + 1;

        freeReplyObject(reply);
    }

    freeReplyObject(redisCommand(c, "del %d", bucket_index));
    redisFree(c);

    return NULL;
}

static int ENTRIES_SIZE = 256*1024*1024/16;
static int BUCKET_SIZE  = 10;
static int PROD_SIZE = 4;
static int CUSM_SIZE = 10; 
static int CUSM_MODE = 1;

void* produce(void *args) {
    redisContext *c = get_redis_connection();

    char buf[16];
    int bucket_index = 0;
    
    long count = ENTRIES_SIZE;
    int bucket_size = BUCKET_SIZE;
    int index = (int) args;

    redisReply *reply;
    while(count > 0) {
        count --;
        if(count % PROD_SIZE != index) continue;
        MD5((const char*)&count, sizeof(int), buf);
        bucket_index = abs(((int*)buf)[0] % bucket_size);
        freeReplyObject(redisCommand(c, "lpush %d %b", bucket_index, buf, sizeof(buf)));
        
    }

    redisFree(c);
    return NULL;
}

int main(int argc, char **argv)
{
    struct timeval tv;

    ENTRIES_SIZE = atoi(argv[1]);
    printf("data in byte: %d\n", ENTRIES_SIZE);

    BUCKET_SIZE = atoi(argv[2]);
    printf("bucket size: %d\n", BUCKET_SIZE);
    CUSM_SIZE = BUCKET_SIZE;

    PROD_SIZE = atoi(argv[3]);
    printf("producers: %d\n", PROD_SIZE);

    CUSM_MODE = atoi(argv[4]);
    printf("consuming mode: %d\n", CUSM_MODE);

    gettimeofday(&tv, NULL);
    printf("start time: %lu\n", tv.tv_sec);
    pthread_t *producers = calloc(PROD_SIZE, sizeof(pthread_t));
    for(int i=0; i<PROD_SIZE; i++) {
        int prodid = i;
        pthread_create(&producers[i], NULL, produce, (void*)prodid);
    }

    for(int j=0; j<PROD_SIZE; j++) {
        pthread_join(producers[j], NULL);
    }
    free(producers);
    //collect_keys();
    gettimeofday(&tv, NULL);
    printf("Producing time: %lu\n", tv.tv_sec);

    pthread_t *customers = calloc(CUSM_SIZE, sizeof(pthread_t));
    for(int i=0; i<CUSM_SIZE; i++) {
        int cusmid = i;
        if(CUSM_MODE == 1)
            pthread_create(&customers[i], NULL, cusume_1, (void*)cusmid);
        else if(CUSM_MODE == 2)
            pthread_create(&customers[i], NULL, cusume_2, (void*)cusmid);
        else 
            pthread_create(&customers[i], NULL, cusume_3, (void*)cusmid);
    }

    for(int j=0; j<CUSM_SIZE; j++) {
        pthread_join(customers[j], NULL);
    }
    free(customers);
    gettimeofday(&tv, NULL);
    printf("end time: %lu\n", tv.tv_sec);

    return 0;
}
