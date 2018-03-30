#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>  

int main(int argc, char **argv) {
    char *pname = "/tmp/testpipe.pipe";
    int rc;
    if(access(pname, F_OK) != 0) {
        rc = mkfifo(pname, 0777);
        if (rc != 0) {
            printf("failed to make pipe\n");
            exit(1);
        }
    }

    int stop = 0;
    rc = fork();
    if(rc == 0) {
        int rc1 = open(pname, O_RDONLY);
        char buff[8192];
        int times = 0;
        while(!stop) {
            size_t rdsz = read(rc1, buff, sizeof(buff));
            printf("%d: read bytes: %ld\n", times, rdsz);
            times ++;
        }
        close(rc1);
    }
    else {
        int rc2 = open(pname, O_WRONLY);
        int count = 10;
        char buff[65537*16];
        while(count > 0) {
            size_t wrsz = write(rc2, buff, sizeof(buff));
            printf("write bytes: %ld\n", wrsz);
            sleep(1);
        }
        stop = 1;
        close(rc2);
    }

    return 0;
}
