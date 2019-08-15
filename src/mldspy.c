#include "mldspy.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if_ether.h>

#define BUFSIZE 1500

/* See RFC 3810 */

/* MALI = Multicast Address Listening Interval */
/* LLQT = Last Listener Query Time */

/* Current State Record */
#define MODE_IS_INCLUDE	1
#define MODE_IS_EXCLUDE	2

/* Filter Mode Change Record */
#define CHANGE_TO_INCLUDE_MODE 3
#define CHANGE_TO_EXCLUDE_MODE 4

/* Source List Change Record */
#define ALLOW_NEW_SOURCES 5
#define BLOCK_OLD_SOURCES 6

/* 9.14.1.  Robustness Variable */
#define MLD2_ROBUSTNESS 2

#define MLD2_LISTEN_REPORT 143 /* Multicast Listener Report messages */

#define MLD2_CAPABLE_ROUTERS "ff02::16" /* all MLDv2-capable routers */

struct mld_group {
	struct in6_addr	mar_address;	/* Multicast Address */
	/* TODO: interface */
	/* TODO: timer (LLQT) */
};

/* Multicast Address Record */
struct mar {
	uint8_t		mar_type;	/* Record Type */
	uint8_t		mar_auxlen;	/* Aux Data Len */
	uint16_t	mar_sources;	/* Number of Sources */
	struct in6_addr	mar_address;	/* Multicast Address */
	struct in6_addr src_address;	/* source address */
};

/* Version 2 Multicast Listener Report Message */
struct mld2 {
	uint8_t		mld2_type;	/* type field */
	uint8_t		mld2_res1;	/* reserved */
	uint16_t	mld2_cksum;	/* checksum field */
	uint16_t	mld2_res2;	/* reserved */
	uint16_t	mld2_rec;	/* Nr of Mcast Address Records */
	struct mar	mld2_mar;	/* First MCast Address Record */
};

void process_multicast_address_record(struct mld2 *mld)
{
	struct mar mrec = mld->mld2_mar;

	uint8_t mode;
	mode = mrec.mar_type;
	fprintf(stderr, " mode=%i", mode);

	uint16_t source_count;
	source_count = ntohs(mrec.mar_sources);
	fprintf(stderr, " sources=%i", source_count);

	switch (mode) {
		case MODE_IS_INCLUDE:
			fprintf(stderr, "\n\tMODE_IS_INCLUDE ");
			break;
		case MODE_IS_EXCLUDE:
			fprintf(stderr, "\n\tMODE_IS_EXCLUDE ");
			break;
		case CHANGE_TO_INCLUDE_MODE:
			fprintf(stderr, "\n\tCHANGE_TO_INCLUDE_MODE ");
			if (source_count == 0) fprintf(stderr, " INCLUDE NULL => PART");
			break;
		case CHANGE_TO_EXCLUDE_MODE:
			fprintf(stderr, "\n\tCHANGE_TO_EXCLUDE_MODE ");
			if (source_count == 0) fprintf(stderr, " EXCLUDE NULL => JOIN(ASM) ");
			break;
		case ALLOW_NEW_SOURCES:
			fprintf(stderr, "\n\tALLOW_NEW_SOURCES ");
			break;
		case BLOCK_OLD_SOURCES:
			fprintf(stderr, "\n\tBLOCK_OLD_SOURCES ");
			break;
		default:
			fprintf(stderr, "\n\t(UNKNOWN MODE) ");
			break;
	}

	struct in6_addr addr;
	char straddr[INET6_ADDRSTRLEN];

	addr = mrec.mar_address;
	inet_ntop(AF_INET6, addr.s6_addr, straddr, INET6_ADDRSTRLEN);
	fprintf(stderr, "\n\tmulticast group addr=%s", straddr);

	/* TODO: loop through source addresses */
	/*
	struct in6_addr src;
	src = mrec.src_address;

	inet_ntop(AF_INET6, src.s6_addr, straddr, INET6_ADDRSTRLEN);
	fprintf(stderr, " source=%s", straddr);
	*/

	/* TODO: update MLD2 state machine */

}

int main(int argc, char **argv)
{
	int ret = 0;
	int s = 0;
	ssize_t bytes = 0;
	struct ipv6_mreq req;
	struct msghdr msg;
	struct iovec iov;
	struct icmp6_hdr *icmp6;
	char buf_recv[BUFSIZE];
	char buf_ctrl[BUFSIZE];
	char buf_name[BUFSIZE];

	s = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	assert(s != 0);

	/* join "all MLDv2-capable routers" group */
	inet_pton(AF_INET6, MLD2_CAPABLE_ROUTERS, &(req.ipv6mr_multiaddr));
	req.ipv6mr_interface = 0; /* default interface */
	ret = setsockopt(s, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &req, sizeof(req));
	assert(ret != -1);

	iov.iov_base = buf_recv;
	iov.iov_len = sizeof(buf_recv);
	msg.msg_control = buf_ctrl;
	msg.msg_controllen = sizeof(BUFSIZE);
	msg.msg_name = buf_name;
	msg.msg_namelen = sizeof(BUFSIZE);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	for (;;) {
		bytes = recvmsg(s, &msg, 0);
		if (bytes < 0) {
			perror("recvmsg");
			if (errno == EINTR)
				continue;
			else {
				fprintf(stderr, "recvmsg error\n");
				break;
			}
		}
		else {
			icmp6 = (struct icmp6_hdr *) buf_recv;
			fprintf(stderr, "msg received (%i bytes, %i type) ",
				(int)bytes, (int)icmp6->icmp6_type);
			switch (icmp6->icmp6_type) {
				case ND_ROUTER_SOLICIT:
					fprintf(stderr, "\tND_ROUTER_SOLICIT");
					break;
				case ND_ROUTER_ADVERT:
					fprintf(stderr, "\tND_ROUTER_ADVERT");
					break;
				case ND_NEIGHBOR_SOLICIT:
					fprintf(stderr, "\tND_NEIGHBOR_SOLICIT");
					break;
				case ND_NEIGHBOR_ADVERT:
					fprintf(stderr, "\tND_NEIGHBOR_ADVERT");
					break;
				case ND_REDIRECT:
					fprintf(stderr, "\tND_REDIRECT");
					break;
				case MLD2_LISTEN_REPORT:
					fprintf(stderr, "\tMLD2_LISTEN_REPORT");

					/* number of mcast address records */
					uint16_t rec = ntohs(icmp6->icmp6_data16[1]);
					fprintf(stderr, " records=%i", rec);

					/* TODO: loop through mcat address records */

					/* grab the Multicast Address Record */
					struct mld2 *mld = (struct mld2 *)buf_recv;
					process_multicast_address_record(mld);
					break;
				default:
					break;
			}
			fprintf(stderr, "\n");
		}
	}
		
	return 0;
}
