#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// testbin/getopt -a 1 -b 1 -c

int main(int argc, char **argv)
{
    int ch;
    while((ch=getopt(argc, argv, "a:b:c")) != -1) {
        printf("optind: %d\n", optind);
        printf("optarg: %s\n", optarg);
        printf("ch: %c\n", ch);
    }
    return 0;
}
