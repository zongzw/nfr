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
int port = 9379;

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

void* function(void *arg) {
    redisContext *context2 = (redisContext*) arg;
    redisReply *reply;
    printf("2\n");
    while(redisGetReply(context2, (void **)&reply) == REDIS_OK) {
        printf("redis_ok\n");
        if(reply->type == REDIS_REPLY_INTEGER) {
            printf("reply->integer: %lld\n", reply->integer);
        }
        if(reply->type == REDIS_REPLY_STRING && strcmp(reply->str, "PONG") == 0) {
            printf("reply->str: %s\n", reply->str);
            break;
        }
        freeReplyObject(reply);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    redisContext *context = get_redis_connection();
    
    
    redisReply *reply;
    
    char script[1024];
    char sha[64];
    strcpy(script, "if(redis.call('exists', KEYS[1]) == 1) then redis.call('rpush', KEYS[1], ARGV[1]); end");
    
    reply = redisCommand(context, "SCRIPT LOAD %s", script);
    
    printf("reply of script load: %s\n", reply->str);
    strcpy(sha, reply->str);
    freeReplyObject(reply);
    
    
    pthread_t thr;
    pthread_create(&thr, NULL, function, context);
    
    redisAppendCommand(context,"lpush 0 0");
    redisAppendCommand(context,"EVALSHA %s %d %d %d", sha, 1, 0, 1);
    redisAppendCommand(context,"EVALSHA %s %d %d %d", sha, 1, 0, 2);
    redisAppendCommand(context,"EVALSHA %s %d %d %d", sha, 1, 1, 1);
    redisAppendCommand(context,"llen 0");
    redisAppendCommand(context,"llen 1");
    
    redisAppendCommand(context,"ECHO PONG");
    
    
    pthread_join(thr, NULL);
    redisFree(context);
    //redisFree(context2);

    return 0;
}
