/*
 * mcast.h
 *
 *  Created on: 2013-3-4
 *      Author: qiujin
 */

#ifndef MCAST_H_
#define MCAST_H_

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include	<net/if.h>
#include <arpa/inet.h>
#include <time.h>
#include <net/if.h>
#include <errno.h>

#define SA struct sockaddr
int
mcast_join(int sockfd, const SA *sa, socklen_t salen,
		   const char *ifname, u_int ifindex);

int
mcast_leave(int sockfd, const SA *sa, socklen_t salen);
#endif /* MCAST_H_ */
