#ifndef _SOCK_H
#define _SOCK_H

#include <sys/proc.h>
#include <sys/user.h>
#include <sys/file.h>
#include <sys/cred.h>
#include <sys/ksocket.h>
//struct sonode * find_sock_by_fd(int fd, struct cred * cred);
ssize_t sock_send_pid_fd(pid_t pid, int sockfd, struct nmsghdr *msg, struct uio * uiop, int flags);
#endif
