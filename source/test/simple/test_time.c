#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
//#include <time.h>

int main(int argc, char **argv) {
    //time_t t = time(NULL);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    printf("time: %ld, %ld\n", tv.tv_sec, tv.tv_usec);
    //printf("time: %ld\n", t);
    return 0;
}
