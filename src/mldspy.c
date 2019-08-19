#include "color.h"
#include "mldspy.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

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

#define MLD2_HEADER_SIZE 8

#if !__USE_KERNEL_IPV6_DEFS
/* IPv6 packet information.  */
struct in6_pktinfo
{
	struct in6_addr ipi6_addr;  /* src/dst IPv6 address */
	unsigned int ipi6_ifindex;  /* send/recv interface index */
};
#endif

typedef enum {
	FILTER_MODE_INCLUDE = 1,
	FILTER_MODE_EXCLUDE,
} filter_mode_t;

typedef struct mld_source_t {
	struct in6_addr		addr;		/* source address */
	uint32_t		src_timer;	/* source timer */
	struct mld_group_t *	group;		/* parent MLD group */
	struct mld_source_t *	next;
	struct mld_source_t *	prev;
} mld_source_t;

typedef struct mld_group_t {
	struct in6_addr		addr;		/* Multicast Address */
	uint32_t		filter_timer;	/* Filter Timer */
	int			iface;		/* Network Interface */
	filter_mode_t		mode;		/* Router Filter Mode */
	struct mld_source_t *	src_inc;	/* Include (Requested) List */
	struct mld_source_t *	src_exc;	/* Exclude List */
	struct mld_group_t *	next;
} mld_group_t;

/* Multicast Address Record */
struct mar {
	uint8_t		mar_type;	/* Record Type */
	uint8_t		mar_auxlen;	/* Aux Data Len */
	uint16_t	mar_sources;	/* Number of Sources */
	struct in6_addr	mar_address;	/* Multicast Address */
} __attribute__((__packed__));

/* Version 2 Multicast Listener Report Message */
struct mld2 {
	uint8_t		mld2_type;	/* type field */
	uint8_t		mld2_res1;	/* reserved */
	uint16_t	mld2_cksum;	/* checksum field */
	uint16_t	mld2_res2;	/* reserved */
	uint16_t	mld2_rec;	/* Nr of Mcast Address Records */
	struct mar	mld2_mar;	/* First MCast Address Record */
} __attribute__((__packed__));

static int sock = 0;
static mld_group_t *groups = NULL;

/* free source linked-list */
void free_source(mld_source_t *g)
{
	for (mld_source_t *ptr = g; g; ptr = g) {
		g = ptr->next;
		free(ptr);
	}
	g = NULL;
}

/* free group linked-list */
void free_group(mld_group_t *g)
{
	for (mld_group_t *ptr = g; g; ptr = g) {
		g = ptr->next;
		free_source(ptr->src_inc);
		free_source(ptr->src_exc);
		free(ptr);
	}
	g = NULL;
}

/* return new or matching group record */
mld_group_t * group_record(struct in6_addr addr, int iface)
{
	mld_group_t *g, *t;

	if (groups) {
		/* find matching group+interface in linked list */
		for (t = groups; t->next; t = t->next) {
			/* match found, return it */
			if ((memcmp(&(t->addr), &addr, sizeof(struct in6_addr)) == 0)
			&& (t->iface == iface))
			{
				return t;
			}
		}
		/* no match, allocate new struct */
		g = calloc(1, sizeof(struct mld_group_t));
		t->next = g;
	}
	else {
		/* first time, allocate new struct */
		g = calloc(1, sizeof(struct mld_group_t));
		groups = g;
	}
	g->addr = addr;
	g->iface = iface;

	return g;
}

mld_source_t * get_source_record(mld_source_t *list, struct in6_addr *addr)
{
	mld_source_t *l, *prev = NULL;

	for (l = list; l; l = l->next) {
		l->prev = prev;
		prev = l;
		if (memcmp(&(list->addr), addr, sizeof(struct in6_addr)) == 0)
			break;
	}

	return l;
}

void add_source_record(mld_group_t *group, struct in6_addr *addr)
{
	mld_source_t **list, *src;

	list = (group->mode == FILTER_MODE_INCLUDE) ? &(group->src_inc) : &(group->src_exc);
	src = get_source_record(*list, addr);
	if (src) {
		/* TODO: update timer */
		fprintf(stderr, ANSI_COLOR_MAGENTA " (existing source)\n" ANSI_COLOR_RESET);
	}
	else {
		src = calloc(1, sizeof(mld_source_t));
		src->addr = *addr;
		src->group = group;
		/* TODO: add timer */
		*list = src;
	}
}

void del_source_record(mld_group_t *group, struct in6_addr *addr)
{
	mld_source_t **list, *src;

	list = (group->mode == FILTER_MODE_INCLUDE) ? &(group->src_inc) : &(group->src_exc);
	src = get_source_record(*list, addr);
	if (src) {
		fprintf(stderr, ANSI_COLOR_MAGENTA" (deleting source)\n" ANSI_COLOR_RESET);
		if (src->next) {
			/* remove links to this source before freeing */
			src->prev->next = src->next;
			src->next->prev = src->prev;
		}
		if (src == *list)
			*list = src->next; /* update group link */
		free(src);
	}
}

void handle_sigint()
{
	free_group(groups);
	close(sock);

	_exit(0);
}

/* extract interface number from ancillary control data */
int interface_index(struct msghdr msg)
{
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pi;
	int ifidx = 0;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6 || cmsg->cmsg_type != IPV6_PKTINFO)
			continue;
		pi = (struct in6_pktinfo *) CMSG_DATA(cmsg);
		ifidx = pi->ipi6_ifindex;
	}

	return ifidx;
}


void * process_multicast_address_record(struct mar *mrec, int ifidx)
{
	char straddr[INET6_ADDRSTRLEN];
	struct in6_addr addr;
	struct in6_addr *src;
	struct mld_group_t *g;
	uint16_t source_count;

	source_count = ntohs(mrec->mar_sources);
	addr = mrec->mar_address;

	/* find/allocate record for this address/interface combo */
	g = group_record(addr, ifidx);
	assert(g);

	switch (mrec->mar_type) {
		case MODE_IS_INCLUDE:
			if (g->mode != FILTER_MODE_INCLUDE)
				fprintf(stderr, ANSI_COLOR_YELLOW "");
			g->mode = FILTER_MODE_INCLUDE;
			fprintf(stderr, "\n\tMODE_IS_INCLUDE ");
			break;
		case MODE_IS_EXCLUDE:
			if (g->mode != FILTER_MODE_EXCLUDE)
				fprintf(stderr, ANSI_COLOR_YELLOW "");
			g->mode = FILTER_MODE_EXCLUDE;
			fprintf(stderr, "\n\tMODE_IS_EXCLUDE ");
			break;
		case CHANGE_TO_INCLUDE_MODE:
			if (g->mode != FILTER_MODE_INCLUDE)
				fprintf(stderr, ANSI_COLOR_YELLOW "");
			g->mode = FILTER_MODE_INCLUDE;
			fprintf(stderr, "\n\tCHANGE_TO_INCLUDE_MODE ");
			if (source_count == 0) fprintf(stderr, " INCLUDE NULL => PART");
			break;
		case CHANGE_TO_EXCLUDE_MODE:
			if (g->mode != FILTER_MODE_EXCLUDE)
				fprintf(stderr, ANSI_COLOR_YELLOW "");
			g->mode = FILTER_MODE_EXCLUDE;
			fprintf(stderr, "\n\tCHANGE_TO_EXCLUDE_MODE ");
			if (source_count == 0) fprintf(stderr, " EXCLUDE NULL => JOIN(ASM) ");
			break;
		case ALLOW_NEW_SOURCES:
			fprintf(stderr, ANSI_COLOR_GREEN "");
			if (g->mode == 0)
				g->mode = FILTER_MODE_INCLUDE;
			fprintf(stderr, "\n\tALLOW_NEW_SOURCES mode=%i", g->mode);
			break;
		case BLOCK_OLD_SOURCES:
			fprintf(stderr, ANSI_COLOR_RED "");
			if (g->mode == 0)
				g->mode = FILTER_MODE_EXCLUDE;
			fprintf(stderr, "\n\tBLOCK_OLD_SOURCES ");
			break;
		default:
			fprintf(stderr, "\n\t(UNKNOWN MODE) ");
			break;
	}

	inet_ntop(AF_INET6, addr.s6_addr, straddr, INET6_ADDRSTRLEN);
	fprintf(stderr, "\n\tmulticast group addr=%s", straddr);
	fprintf(stderr, " mode=%i", mrec->mar_type);
	fprintf(stderr, " auxlen=%i", mrec->mar_auxlen);
	fprintf(stderr, " sources=%i", source_count);

	/* loop through source addresses */
	src = &(mrec->mar_address); /* actually ptr to in6_addr *before* src */
	for (int i = 0; i < source_count; i++) {
		inet_ntop(AF_INET6, (++src)->s6_addr, straddr, INET6_ADDRSTRLEN);
		fprintf(stderr, "\n\t\tsource=%s", straddr);

		/* write source addresses */
		if (mrec->mar_type == BLOCK_OLD_SOURCES)
			del_source_record(g, src);
		else
			add_source_record(g, src);
	}

	fprintf(stderr, ANSI_COLOR_RESET "");

	/* return pointer to next record */
	src++;
	return src + mrec->mar_auxlen;
}

int main(int argc, char **argv)
{
	int ret = 0;
	int joins = 0;
	int ifidx = 0;
	ssize_t bytes = 0;
	struct ipv6_mreq req;
	struct msghdr msg;
	struct iovec iov[1];
	struct icmp6_hdr *icmp6;
	struct ifaddrs *ifaddr, *ifa;
	struct mar *mrec;
	char buf_recv[BUFSIZE];
	char buf_ctrl[BUFSIZE];
	char buf_name[BUFSIZE];
	uint16_t rec;

	sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	assert(sock != 0);

	/* request ancilliary control data */
	int opt = 1;
	setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt, sizeof(opt));

	getifaddrs(&ifaddr);
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family !=AF_INET6) continue; /* ipv6 only */

		/* join "all MLDv2-capable routers" group */
		inet_pton(AF_INET6, MLD2_CAPABLE_ROUTERS, &(req.ipv6mr_multiaddr));
		req.ipv6mr_interface = if_nametoindex(ifa->ifa_name);
		ret = setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &req, sizeof(req));
		if (ret != -1) {
			fprintf(stderr, "listening on interface %s\n", ifa->ifa_name);
			joins++;
		}
	}
	freeifaddrs(ifaddr);

	if (joins == 0) {
		fprintf(stderr, "Unable to join on any interfaces\n");
		return 1;
	}

	iov[0].iov_base = buf_recv;
	iov[0].iov_len = BUFSIZE;
	msg.msg_control = buf_ctrl;
	msg.msg_controllen = BUFSIZE;
	msg.msg_name = buf_name;
	msg.msg_namelen = BUFSIZE;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	signal(SIGINT, handle_sigint);

	for (;;) {
		bytes = recvmsg(sock, &msg, 0);
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
			fprintf(stderr, "msg received (%i bytes)\ttype %i => ",
				(int)bytes, (int)icmp6->icmp6_type);
			switch (icmp6->icmp6_type) {
				case ND_ROUTER_SOLICIT:
					fprintf(stderr, "ND_ROUTER_SOLICIT");
					break;
				case ND_ROUTER_ADVERT:
					fprintf(stderr, "ND_ROUTER_ADVERT");
					break;
				case ND_NEIGHBOR_SOLICIT:
					fprintf(stderr, "ND_NEIGHBOR_SOLICIT");
					break;
				case ND_NEIGHBOR_ADVERT:
					fprintf(stderr, "ND_NEIGHBOR_ADVERT");
					break;
				case ND_REDIRECT:
					fprintf(stderr, "ND_REDIRECT");
					break;
				case MLD2_LISTEN_REPORT:
					fprintf(stderr, "MLD2_LISTEN_REPORT");

					ifidx = interface_index(msg);
					fprintf(stderr, " iface=%i", ifidx);

					/* number of mcast address records */
					rec = ntohs(icmp6->icmp6_data16[1]);
					fprintf(stderr, " (records=%i)", rec);

					/* process the Multicast Address Record(s) */
					mrec = (struct mar *)(buf_recv + MLD2_HEADER_SIZE);
					for (int i = 0; i < rec; i++) {

						/* don't read beyond end of packet */
						assert((void *)mrec <= (void *)(icmp6 + bytes));

						mrec = process_multicast_address_record(mrec, ifidx);
					}
					break;
				default:
					fprintf(stderr, "UNKNOWN");
					break;
			}
			fprintf(stderr, "\n");
		}
	}

	return 0;
}
