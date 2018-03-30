#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sched.h> // gcc -g -D_GNU_SOURCE test.c -lpthread
#include <ctype.h>
#include <string.h>

// testbin/set_cpu_affinity 1

void* waste(void *args) {
    int num = sysconf(_SC_NPROCESSORS_CONF);

    int myid = (int) args;
    cpu_set_t mask;

    CPU_ZERO(&mask);
    CPU_SET(myid, &mask);
    if(sched_setaffinity(0, sizeof(mask), &mask) == -1) {
        printf("failed to set cpu affinity.\n");
    }

    cpu_set_t get;
    CPU_ZERO(&get);
    if(sched_getaffinity(0, sizeof(get), &get) == -1) {
        printf("failed to get cpu affinity. \n");
    }

    int i;
    for(i=0; i<num; i++) {
        if(CPU_ISSET(i, &get)) {
            printf("thread %d running on %d\n", myid, i);
        }
    }

    int a = 1024*1024*1024;
    while(a > 0) {
        a % 16;
        a--;
    }
}

int main(int argc, char **argv)
{
    int num = sysconf(_SC_NPROCESSORS_CONF);
    printf("cpu num: %d\n", num); 

    int myid = atoi(argv[1]);

    cpu_set_t mask;
    cpu_set_t get;

    CPU_ZERO(&mask);
    CPU_SET(myid, &mask);
    printf("cpu_set_t: %lu\n", sizeof(cpu_set_t));
    printf("mask: ");
    int i;

    for(i=0; i<sizeof(cpu_set_t); i++) {
        if(i%16 == 0) printf("\n");
        printf("%02X ", ((char*)&mask)[i] & 255);
    }
    printf("\n");

    if(sched_setaffinity(0, sizeof(mask), &mask) == -1) {
        printf("failed to set cpu affinity.\n");
    }

    CPU_ZERO(&get);
    if(sched_getaffinity(0, sizeof(get), &get) == -1) {
        printf("failed to get cpu affinity. \n");
    }

    for(i=0; i<num; i++) {
        if(CPU_ISSET(i, &get)) {
            printf("process %d running on %d\n", getpid(), i);
        }
    }

    pthread_t tid0, tid1, tid2, tid3;
    pthread_create(&tid0, NULL, waste, 0);
    pthread_create(&tid1, NULL, waste, 1);
    pthread_create(&tid2, NULL, waste, 2);
    pthread_create(&tid3, NULL, waste, 3);
    pthread_join(tid0, NULL);
    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
    pthread_join(tid3, NULL);
  
    return 0;
}
