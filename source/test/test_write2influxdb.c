#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>

char connection[128];
char dbname[64];
char ign_out[16];
int stop = 0;

char *fn = "testfile";
static int rd, wr;

void sigproc(int sig) {
    printf("leaving\n");
    stop = 1;
}

int create_database(char *dbname) {
    char cmd[512];
    sprintf(cmd, "curl -X POST %s/query \
            --data-urlencode \"q=CREATE DATABASE IF NOT EXISTS %s\" %s", connection, dbname, ign_out);
    
    return system(cmd);
}

int delete_database(char *dbname) {
    char cmd[512];
    sprintf(cmd, "curl -X POST %s/query \
            --data-urlencode \"q=DROP DATABASE IF EXISTS %s\" %s", connection, dbname, ign_out);
    
    return system(cmd);
}

int write_data(char *dbname, char *datastr) {
    char cmd[512];
    sprintf(cmd, "curl -i -XPOST '%s/write?db=%s&u=root&p=GRgEdjM6' --data-binary '%s' %s", connection, dbname, datastr, ign_out);
    return system(cmd);
}

void* write_thread(void *arg) {
    
    long thrid = (long) arg;
    char datastr[256];
    
    while(!stop) {
        int k = rand() % 100;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        sprintf(datastr, "randn,thread=%ld value=%d %ld%06ld000\n", thrid, k, tv.tv_sec, tv.tv_usec);
        printf("write: %s\n", datastr);
        write(wr, datastr, strlen(datastr));
        //write_data(dbname, datastr);
        sleep(1);
    }
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);
    
    printf("write to influxdb\n");
    
    sprintf(connection, "http://localhost:8086");
    
    //char *dbname = "dbtest";
    strcpy(dbname, "dbtest");
    memset(ign_out, 0, sizeof(ign_out));
    strcpy(ign_out, "> /dev/null 2>&1");
    
    create_database(dbname);
    
    int threadcount = 4;
    pthread_t ts[threadcount];
    
    //int rc = mkfifo(fn, 0777);

    int rc;
    wr = open(fn, O_WRONLY);

    long i;
    for(i=0; i<threadcount; i++) {
        pthread_create(&ts[i], NULL, write_thread, (void*)i);
    }
    
    sleep(20);
    close(wr);
    while(!stop) {
        char cmd[4096];
        sprintf(cmd, "curl -i -XPOST '%s/write?db=%s&u=root&p=GRgEdjM6' --data-binary @%s", connection, dbname, fn);
        rc = system(cmd);
        printf("execute %s: %d\n", cmd, rc);
        sleep(5);
    }

    for(i=0; i<threadcount; i++) {
        pthread_join(ts[i], NULL);
    }
    
    return 0;
}
