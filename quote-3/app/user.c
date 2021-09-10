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

static void 
signal_handle(int signum)
{
	if(signum == SIGINT)
	{
		printf("Preparing to quit...\n");
		force_quit = true;
	}
}

static void
get_size(const char *dev)
{
	size_t sz;
	int fd;

	if ((fd = open(dev, O_RDONLY)) < 0) {
		perror("open");
		exit(3);
	}

	if (ioctl(fd, QOTDIOCGSZ, &sz) < 0) {
		perror("QOTDIOCGSZ");
		exit(4);
	}

	(void) close(fd);

	(void) printf("%zu\n", sz);
}

static void
set_size(const char *dev, size_t sz)
{
	int fd;

	if ((fd = open(dev, O_RDWR)) < 0) {
		perror("open");
		exit(3);
	}

	if (ioctl(fd, QOTDIOCSSZ, &sz) < 0) {
		perror("QOTDIOCSSZ");
		exit(4);
	}

	(void) close(fd);
}

/** devfile ip port*/
static int 
mod_config(int ac, char *av[])
{
	pid_t pid;
	int ret, tmpfd, fd;

	if(ac != 5)
	{
		fprintf(stderr, "mod_config : devfile ip port pid fd\n");
		return -1;
	}
	
	fd = open(av[0], O_RDWR);
	if(fd < 0)
	{
		perror("open");
		exit(errno);
	}

	//�set pid
	pid = atoi(av[3]);
	ret = ioctl(fd, QOTDIOCSPID, &pid);
	if(ret == -1)
	{
		perror("ioctl QOTDIOCSPID");
		close(fd);
		return -1;
	}

	//read pid
	ret = ioctl(fd, QOTDIOCGPID, &pid);
	if(ret == -1)
	{
		perror("ioctl QOTDIOCGPID");
		close(fd);
		return -1;
	}
	printf("read pid : %d\n", pid);

	//设置sockfd
	//sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	//if(socket < 0)
	//{
	//	perror("socket");
	//	close(fd);
	//	return -1;
	//}
	sockfd = atoi(av[4]);
	ret = ioctl(fd, QOTDIOCSFD, &sockfd);
	if(ret == -1)
	{
		perror("ioctl QOTDIOCFD");
		close(fd);
		return -1;
	}

	//read sockfd
	ret = ioctl(fd, QOTDIOCGFD, &tmpfd);
	if(ret == -1)
	{
		perror("ioctl QOTDIOCGFD");
		close(fd);
		return -1;
	}
	printf("read sockfd : %d\n", tmpfd);

	//设置IP
	uint32_t ip = inet_addr(av[1]);
	struct in_addr in;
	ret = ioctl(fd, QOTDIOCSIP, &ip);
	if(ret == -1)
	{
		close(fd);
		perror("ioctl QOTDIOCSIP");
		return -1;
	}

	ret = ioctl(fd, QOTDIOCGIP, &ip);
	if(ret == -1)
	{
		close(fd);
		perror("ioctl QOTDIOCGIP");
		return -1;
	}
	in.s_addr = ip;
	printf("read ip : %s\n", inet_ntoa(in));
	//set port
	uint16_t port = htons(atoi(av[2])); 
	ret = ioctl(fd, QOTDIOCSPORT, &port);
	if(ret == -1)
	{
		close(fd);
		perror("ioctl QOTDIOCSPORT");
		return -1;
	}

	ret = ioctl(fd, QOTDIOCGPORT, &port);
	if(ret == -1)
	{
		close(fd);
		perror("ioctl QOTDIOCGPORT");
		return -1;
	}
	printf("read port : %u\n", ntohs(port));
	close(fd);
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
	int ret, devfd;
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

	get_size(devfile);
	set_size(devfile, 1500);

	//config mod
	--ac;
	++av;
	if(mod_config(ac, av) == -1)
	{
		fprintf(stderr, "mod_config failed\n");
		goto done;
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
		usleep(100);
	}

	ret = read(devfd, buf, BUF_SIZE);
	if(ret < 0){
		perror("read");
	}
	else
	{
		printf("data from kernel : %s\n",buf);
	}

done:
	reset_dev(devfile);
	close(devfd);
	close(sockfd);
	printf("done.\n");
	return 0;
}
