#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include "qotd.h"

#define BUF_SIZE    128
#define IP          "127.0.0.1"
#define PORT        7788

static char buf[256];
static bool force_quit          = false;
static const char * devfile     = NULL;
static int sockfd               = -1;
static int devfd                = -1;

static void 
signal_handle(int signum)
{
    if(signum == SIGINT)
    {
        printf("Preparing to quit...\n");
        force_quit = true;
    }
}

static int 
mod_config(void)
{
    pid_t pid;
    int ret, tmpdevfd;

    //设置pid
    pid = getpid();
    ret = ioctl(devfd, QOTDIOCSPID, pid);
    if(ret == -1)
    {
        perror("ioctl QOTDIOCSPID");
        return -1;
    }

    //�read pid
    ret = ioctl(devfd, QOTDIOCGPID, &pid);
    if(ret == -1)
    {
        perror("ioctl QOTDIOCGPID");
        return -1;
    }
    printf("read pid : %d\n", pid);

    //设置sockfd
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(socket < 0)
    {
        perror("socket");
        return -1;
    }
    ret = ioctl(devfd, QOTDIOCSFD, sockfd);
    if(ret == -1)
    {
        perror("ioctl QOTDIOCFD");
        return -1;
    }

    //read �sockfd
    ret = ioctl(devfd, QOTDIOCGFD, &tmpdevfd);
    if(ret == -1)
    {
        perror("ioctl QOTDIOCGFD");
        return -1;
    }
    printf("read sockfd : %d\n", tmpdevfd);

    //设置IP
    uint32_t ip = inet_addr(IP);
    struct in_addr in;
    ret = ioctl(devfd, QOTDIOCSIP, ip);
    if(ret == -1)
    {
        perror("ioctl QOTDIOCSIP");
        return -1;
    }
    
    ret = ioctl(devfd, QOTDIOCGIP, &ip);
    if(ret == -1)
    {
        perror("ioctl QOTDIOCGIP");
        return -1;
    }
    in.s_addr = ip;
    printf("read ip : %s\n", inet_ntoa(in));
    //set port
    uint16_t port = htons(PORT); 
    ret = ioctl(devfd, QOTDIOCSPORT, port);
    if(ret == -1)
    {
        perror("ioctl QOTDIOCSPORT");
        return -1;
    }
    
    ret = ioctl(devfd, QOTDIOCGPORT, &port);
    if(ret == -1)
    {
        perror("ioctl QOTDIOCGPORT");
        return -1;
    }
    printf("read port : %u\n", ntohs(port));
    return 0;
}

static void
reset_dev(const char *dev)
{
	int fd;

	if ((fd = open(dev, O_RDWR)) < 0) {
		perror("open");
		exit(3);
	}

	if (ioctl(fd, QOTDIOCDISCARD) < 0) {
		perror("QOTDIOCDISCARD");
		exit(4);
	}

	(void) close(fd);
}

int main(int ac, char *av[])
{
    int ret;
    time_t tm;

    if(ac < 2)
    {
        printf("Usage : ./program devfile\n");
        return -1;
    }

    signal(SIGINT, signal_handle);

    devfile = av[1];
    printf("devfile = %s\n", devfile);
    devfd = open(devfile, O_RDWR);
    if(devfd < 0)
    {
        perror("open");
        exit(errno);
    }

    //config mod
    if(mod_config() == -1)
    {
        fprintf(stderr, "mod_config failed\n");
        close(devfd);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    while(!force_quit)
    {
        tm = time(NULL);
        sprintf(buf, "%s", ctime(&tm));
        ret = write(devfd, buf, strlen(buf) + 1);
        if(ret < 0){
			fprintf(stderr, "ret = %d\n", ret);
            perror("write");
            break;
        }
        sleep(1);
    }

    ret = read(devfd, buf, BUF_SIZE);
    if(ret < 0){
        perror("read");
    }
    else
    {
        printf("data from kernel : %s\n",buf);
    }

	reset_dev(devfile);
    
    close(devfd);
    close(sockfd);
    printf("done.\n");
    return 0;
}
