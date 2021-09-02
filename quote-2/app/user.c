#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define BUF_SIZE 128

static char buf[BUF_SIZE];

int main(int ac, char *av[])
{
    int fd, ret;

    if(ac != 3)
    {
        printf("Usage : ./program devfile msg2kernel\n");
        return -1;
    }
    
    fd = open(av[1], O_RDWR);
    if(fd < 0)
    {
        perror("open");
        exit(errno);
    }
    
    ret = write(fd, av[2], strlen(av[2]) + 1);
    if(ret < 0){
        perror("write");
    }

    ret = read(fd, buf, BUF_SIZE);
    if(ret < 0){
        perror("read");
    }
    else
    {
        printf("data from kernel : %s\n", buf);
    }
    
    close(fd);
    return 0;
}
