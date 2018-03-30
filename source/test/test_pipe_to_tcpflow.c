#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

/*
 *  this is an encapsulation for 'tcpdump -i eth0 -w - | tcpflow -r -'
 */
int main(int argc, char **argv) {
    pid_t pid;
    int pipes[2];
    
    printf("fork child process\n");
    
    int rc = pipe(pipes);
    if(rc == -1) {
        printf("pipe failed.\n");
        return -1;
    }
    pid = fork();
    if(pid < 0) {
        printf("fork failed.\n");
        return -1;
    }
    
    if(pid == 0) {
        // child
        printf("child working.\n");
        close(pipes[1]);
        dup2(pipes[0], 0);
        system("tcpflow -r -");
        printf("child work done\n");
        
    }
    else {
        printf("parent working.\n");
        close(pipes[0]);
        dup2(pipes[1], 1);
        system("tcpdump -i eth0 -w -");
        printf("parent working done\n");
    }
    return 0;
}