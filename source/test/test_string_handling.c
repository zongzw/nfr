#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
//#include <hiredis.h>
//#include <openssl/md5.h> //gcc -lcrypto
//#define _GNU_SOURCE
//#define __USE_GNU
#include <sched.h> // gcc -g -D_GNU_SOURCE test.c -lpthread
#include <ctype.h>
#include <string.h>


int main(int argc, char **argv)
{
  
    /*
    struct timeval tv;

    ENTRIES_SIZE = atoi(argv[1]);
    printf("data in byte: %d\n", ENTRIES_SIZE);

    gettimeofday(&tv, NULL);
    printf("start time: %lu\n", tv.tv_sec);
    collect_keys();
    gettimeofday(&tv, NULL);
    printf("collecting time: %lu\n", tv.tv_sec);

    pthread_t tids[BUCKET_SIZE];
    for(int i=0; i<BUCKET_SIZE; i++) {
        int bucket_index = i;
        pthread_create(&tids[i], NULL, handle_keys_1, (void*)bucket_index);
    }

    for(int j=0; j<BUCKET_SIZE; j++) {
        pthread_join(tids[j], NULL);
    }
    gettimeofday(&tv, NULL);
    printf("end time: %lu\n", tv.tv_sec);
    */

    /*
    char ippair[64];
    int tv;
    memset(ippair, 0, 64);
    char *key = "pcap-handling-234242343-pcap-data-12.23.4.2-23.4.5.2";
    sscanf(key, "pcap-handling-%d-pcap-data-%s", &tv, ippair);
    printf("%d, %s\n", tv, ippair);
    //struct timeval tv;
    //gettimeofday(&tv, NULL);
    //printf("%lu, %lu\n", tv.tv_sec, tv.tv_usec);
    */
    /*
    char *path = argv[1];
    struct stat info;
    stat(path,&info);
    if(S_ISDIR(info.st_mode))
        printf("This is a directory");
    */
    /*
    int ch;
    while((ch=getopt(argc, argv, "a:b:c")) != -1) {
        printf("optind: %d\n", optind);
        printf("optarg: %s\n", optarg);
        printf("ch: %c\n", ch);
    }
    */
    //for(int i=0; i<10; i++);
    //tprocess2(NULL);
    /*
    redisContext *c;
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    c = redisConnectWithTimeout("127.0.0.1", 6379, timeout);
    redisReply *reply;
    reply = redisCommand(c, "keys *:*");
    printf("reply: %s\n", reply->str);
    freeReplyObject(reply);
    */
    ///int a[64]; 
    //printf("sizeof(a[64]): %i\n", sizeof(a));
    /*
    pthread_t t1;
    pthread_t t2;
    pthread_create(&t1, NULL, tprocess1, NULL);
    pthread_create(&t2, NULL, tprocess2, NULL);
    pthread_join(t1, NULL);
    */
    /*
    char conn[] = "127.0.0.1:6379";
    char ip[16];
    char pt[16];
    char *p = strchr(conn, ':');
    memset(ip, 0, sizeof(ip));
    memset(pt, 0, sizeof(pt));
    strncpy(ip, conn, p-conn);
    strcpy(pt, p+1);

    printf("ip: %s, port: %s\n", ip, pt);
    */
    //struct timeval a;
    //printf("%i\n", sizeof(struct timeval));
    return 0;
}
