#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#define BUF_SIZE 1024
#define PORT 1100

static bool force_quit = false;
static const char * filename = "info.txt"; 

/* On all other architectures */
//int pipe(int pipefd[2]);
void signal_handle(int signum)
{
	if(signum == SIGINT)
	{
		printf("Preparing to quit...\n");
		force_quit = true;
	}
}

int main(int ac, char * av[])
{
	struct sockaddr_in localaddr, remoteaddr;
	int sockfd, ret;
	socklen_t addrlen;
	char buf[BUF_SIZE];
	time_t tm;
	FILE * fp;

	if(ac != 4)
	{
		printf("Usage : ./program mode ip port\n");
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, signal_handle);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);//面向消息的UDP
	if(socket < 0)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}
	fp = fopen(filename, "w");
	if(!fp)
	{
		perror("fopen");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	fprintf(fp, "pid, sockfd: %d, %d", getpid(), sockfd);
	fprintf(stdout, "pid, sockfd: %d, %d\n", getpid(), sockfd);
	fclose(fp);

	addrlen = sizeof(struct sockaddr_in);

	if(strncmp("recv", av[1], 4) == 0)
	{
		printf("mode is recv\n");

		localaddr.sin_family = AF_INET;
		localaddr.sin_addr.s_addr = inet_addr(av[2]);
		localaddr.sin_port = htons(atoi(av[3]));
		ret = bind(sockfd, (struct sockaddr *)&localaddr, sizeof(struct sockaddr));
		if(ret == -1)
		{
			perror("bind ");
			exit(errno);
		}
		printf("bind(%s:%d)\n", 
					inet_ntoa(localaddr.sin_addr), 
					ntohs(localaddr.sin_port));
		while(!force_quit)
		{
			ret = recvfrom(sockfd, 
						buf,
						BUF_SIZE - 1,
						0,
						(struct sockaddr *) &remoteaddr, &addrlen);
			if(ret <= 0)
			{
				perror("recvfrom ");
				break;
			}
#ifdef DEBUG
			else
			{
				printf("recvfrom (%s:%d), len=%d : %s\n", 
							inet_ntoa(remoteaddr.sin_addr), 
							ntohs(remoteaddr.sin_port), ret, buf);
			}
#endif
		}
	}
	else if(strncmp("send", av[1], 4) == 0)
	{
		printf("mode is send\n");
		remoteaddr.sin_family = AF_INET;
		remoteaddr.sin_addr.s_addr = inet_addr(av[2]);
		remoteaddr.sin_port = htons(atoi(av[3]));

		while(!force_quit)
		{
			memset(buf, 0, BUF_SIZE);
			tm = time(NULL);
			sprintf(buf, "%s", ctime(&tm));
			ret = sendto(sockfd, 
						buf,
						strlen(buf) + 1,
						0,
						(const struct sockaddr *) &remoteaddr,
						addrlen);
			if(ret <= 0)
			{
				perror("sendto");
				break;
			}
#ifdef DEBUG
			else
			{
				printf("sendto (%s:%d), len=%d : %s\n", 
							inet_ntoa(remoteaddr.sin_addr), 
							ntohs(remoteaddr.sin_port), ret, buf);
			}
#endif
			usleep(200);
		}
	}
	else
	{
		fprintf(stderr, "unkown mode %s\n", av[1]);
	}
	close(sockfd);
	return 0;
}
