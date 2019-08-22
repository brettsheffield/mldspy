/* SPDX-License-Identifier: GPL-2.0-or-later 
 * Copyright (c) 2019 Brett Sheffield <brett@gladserv.com> */

#include "log.h"
#include "mldspy.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <curses.h>
#include <locale.h>
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
#include <time.h>
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

#define TIMER_SIG SIGRTMIN

#define MLD_RECORD_EXPIRE 150

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
	time_t			last;		/* source last refreshed */
	struct mld_group_t *	group;		/* parent MLD group */
	struct mld_source_t *	next;
	struct mld_source_t *	prev;
} mld_source_t;

typedef struct mld_group_t {
	struct in6_addr		addr;		/* Multicast Address */
	time_t			last;		/* group last refreshed */
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
static timer_t tid;
static int timer_expiry = 0;
static int opt_noexpire = 0;

void display_init() __attribute__((always_inline));

void inline display_init()
{
	int x, y, odd;

	setlocale(LC_ALL, "");
	initscr(); cbreak(); noecho(); curs_set(0);
	nonl(); intrflush(stdscr, FALSE); keypad(stdscr, TRUE);

	getmaxyx(stdscr, y, x);
	odd = y % 2;
	win_stat = newwin(y/2 - odd, x, 0, 0);
	win_logs = newwin(y/2 + odd, x, y/2, 0);
	scrollok(win_logs, TRUE);

	start_color();
	init_pair(WHITE_ON_BLACK, COLOR_WHITE, COLOR_BLACK);
	init_pair(BLACK_ON_WHITE, COLOR_BLACK, COLOR_WHITE);
	init_pair(YELLOW_ON_BLACK, COLOR_YELLOW, COLOR_BLACK);
	init_pair(GREEN_ON_BLACK, COLOR_GREEN, COLOR_BLACK);
	init_pair(RED_ON_BLACK, COLOR_RED, COLOR_BLACK);
	wattron(win_stat, COLOR_PAIR(WHITE_ON_BLACK));
	wattron(win_logs, COLOR_PAIR(WHITE_ON_BLACK));

	wclear(win_stat);
	wclear(win_logs);
	wrefresh(win_stat);
	wrefresh(win_logs);
}

void display_update()
{
	int x, y, len;
	char buf[128];
	char straddr[INET6_ADDRSTRLEN];
	char ifname[IF_NAMESIZE];
	char *mode;

	getmaxyx(win_stat, y, x);
	len = snprintf(buf, sizeof(buf), "%s v%s", PROGRAM_NAME, PROGRAM_VERSION);

	wclear(win_stat);
	wattron(win_stat, COLOR_PAIR(BLACK_ON_WHITE));
	for (int i = 0; i < x; i++) {
		mvwprintw(win_stat, 0, i, " ");		/* status header */
		mvwprintw(win_stat, y - 1, i, "-");	/* status footer */
	}
	mvwprintw(win_stat, 0, x/2 - len/2, buf);	/* program name */
	wattron(win_stat, COLOR_PAIR(WHITE_ON_BLACK));

	/* display cached MLD records */
	mld_group_t *g;
	mld_source_t *src;
	if ((g = groups)) {
		for (int i = 0; g; g = g->next) {
			inet_ntop(AF_INET6, g->addr.s6_addr, straddr, INET6_ADDRSTRLEN);
			if_indextoname(g->iface, ifname);
			mvwprintw(win_stat, ++i, 0, "%s", straddr);
			mvwprintw(win_stat, i, 38, "| %s", ifname);
			mode = (g->mode == FILTER_MODE_EXCLUDE) ? "EXCLUDE" : "INCLUDE";
			mvwprintw(win_stat, i, 48, "| %s", mode);
			src = (g->mode == FILTER_MODE_EXCLUDE) ? g->src_exc : g->src_inc;
			for (; src; src = src->next) {
				inet_ntop(AF_INET6, src->addr.s6_addr, straddr, INET6_ADDRSTRLEN);
				mvwprintw(win_stat, ++i, 2, "- %s (%sD source)", straddr, mode);
			}
			if (i > (y - 2)) break;
		}
	}

	wrefresh(win_stat);
}

/* free source linked-list */
void free_source(mld_source_t *g)
{
	for (mld_source_t *ptr = g; g; ptr = g) {
		g = ptr->next;
		free(ptr);
	}
	g = NULL;
}

/* free single group */
void free_group(mld_group_t *g)
{
	free_source(g->src_inc);
	free_source(g->src_exc);
	free(g);
	g = NULL;
}

/* free group linked-list */
void free_groups(mld_group_t *g)
{
	for (mld_group_t *ptr = g; g; ptr = g) {
		g = ptr->next;
		free_group(ptr);
	}
	g = NULL;
}

void set_timer(time_t *t)
{
	struct itimerspec ts = {};

	*t = time(NULL); /* update record timestamp */

	/* set timer if not already set */
	timer_gettime(tid, &ts);
	if (ts.it_value.tv_sec == 0 && ts.it_value.tv_nsec == 0) {
		ts.it_value.tv_sec = MLD_RECORD_EXPIRE;
		timer_settime(tid, 0, &ts, NULL);

		logmsg(LOG_DEBUG, " RESTARTING TIMER \n");
	}
}

/* return new or matching group record */
mld_group_t * group_record(struct in6_addr addr, int iface)
{
	mld_group_t *g, *t, *prev;

	if (groups) {
		/* find matching group+interface in linked list */
		for (prev = t = groups; t; t = t->next) {
			/* match found, return it */
			if ((memcmp(&(t->addr), &addr, sizeof(struct in6_addr)) == 0)
			&& (t->iface == iface))
			{
				return t;
			}
			prev = t;
		}
		/* no match, allocate new struct */
		g = calloc(1, sizeof(struct mld_group_t));
		if (prev) prev->next = g;
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
		set_timer(&(src->last));
		logmsg(LOG_INFO, " (existing source)\n");
	}
	else {
		src = calloc(1, sizeof(mld_source_t));
		src->addr = *addr;
		src->group = group;
		set_timer(&(src->last));
		*list = src;
	}
}

void del_source_record(mld_group_t *group, struct in6_addr *addr)
{
	mld_source_t **list, *src;

	list = (group->mode == FILTER_MODE_INCLUDE) ? &(group->src_inc) : &(group->src_exc);
	src = get_source_record(*list, addr);
	if (src) {
		logmsg(LOG_INFO, " (deleting source)\n");
		if (src->next) {
			/* remove links to this source before freeing */
			src->prev->next = src->next;
			src->next->prev = src->prev;
		}
		if (src == *list)
			*list = src->next; /* update group link */
		free(src);
	}
	else
		logmsg(LOG_INFO, " (source does not exist, skipping)\n");
}

time_t expire_sources(mld_source_t **top)
{
	mld_source_t *prev = NULL, *src;
	time_t now = time(NULL); /* check time once */
	time_t t = now - MLD_RECORD_EXPIRE; /* expire anything older */
	time_t tnext = now;

	for (src = *top; src; ) {
		if (t > src->last) {
			/* source expired */
			logmsg(LOG_INFO, "\t source expired\n");
			if (!prev) { /* first record */
				*top = src->next;
				free_source(src);
				src = *top;
				continue;
			}
			prev->next = src->next;
			free_source(src);
			src = prev->next;
		}
		if (src->last < tnext) tnext = src->last;
		prev = src;
		src = src->next;
	}
	return tnext;
}

/* loop through group and source records, deleting any expired */
void expire_records() {
	struct itimerspec ts = {};
	mld_group_t *g, *prev = NULL;
	time_t now = time(NULL); /* check time once */
	time_t t = now - MLD_RECORD_EXPIRE; /* expire anything older */
	time_t tnext = now;
	time_t sec = 0;
	char straddr[INET6_ADDRSTRLEN];

	timer_expiry = 0;

	if (opt_noexpire) return;

	logmsg(LOG_DEBUG, "\n-- timer --\n");
	if (groups) {
		for (g = groups; g; ) {
			inet_ntop(AF_INET6, g->addr.s6_addr, straddr, INET6_ADDRSTRLEN);
			logmsg(LOG_DEBUG, "%s (%i) ", straddr, g->iface);
			if (t > g->last) {
				/* record expired */
				sec = t - g->last;
				logmsg(LOG_DEBUG, "EXPIRED %lis ago\n", sec);
				if (!prev) { /* first record */
					groups = g->next;
					free_group(g);
					g = groups;
					continue;
				}
				prev->next = g->next;
				free_group(g);
				g = prev;
			}
			else {
				/* record not expired */
				sec = expire_sources(&(g->src_inc));
				if (sec < tnext) tnext = sec;
				sec = expire_sources(&(g->src_exc));
				if (sec < tnext) tnext = sec;
				sec = now - g->last;
				logmsg(LOG_DEBUG, "age %lis\n", sec);
				if (g->last < tnext) tnext = g->last;
			}
			prev = g;
			g = g->next;
		}
	}

	/* reset timer based on next record to expire */
	ts.it_value.tv_sec = MLD_RECORD_EXPIRE - (now - tnext) + 1;
	logmsg(LOG_DEBUG, "-- next timer: %lis --\n", ts.it_value.tv_sec);
	timer_settime(tid, 0, &ts, NULL);

	display_update();
}

void handle_sigint()
{
	timer_delete(tid);
	free_groups(groups);
	close(sock);

	/* ncurses cleanup */
	delwin(win_logs);
	delwin(win_stat);
	endwin();

	_exit(0);
}

void handle_timer()
{
	timer_expiry = 1;
	return;
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
	g = group_record(addr, ifidx); assert(g);
	set_timer(&(g->last)); /* refresh timestamp */

	switch (mrec->mar_type) {
		case MODE_IS_INCLUDE:
			g->mode = FILTER_MODE_INCLUDE;
			logmsg(LOG_INFO, "\n\tMODE_IS_INCLUDE ");
			break;
		case MODE_IS_EXCLUDE:
			g->mode = FILTER_MODE_EXCLUDE;
			logmsg(LOG_INFO, "\n\tMODE_IS_EXCLUDE ");
			break;
		case CHANGE_TO_INCLUDE_MODE:
			if (g->mode != FILTER_MODE_EXCLUDE)
				wattron(win_logs, COLOR_PAIR(YELLOW_ON_BLACK));
			g->mode = FILTER_MODE_INCLUDE;
			logmsg(LOG_INFO, "\n\tCHANGE_TO_INCLUDE_MODE ");
			if (source_count == 0) logmsg(LOG_INFO, " INCLUDE NULL => PART");
			break;
		case CHANGE_TO_EXCLUDE_MODE:
			if (g->mode != FILTER_MODE_EXCLUDE)
				wattron(win_logs, COLOR_PAIR(YELLOW_ON_BLACK));
			g->mode = FILTER_MODE_EXCLUDE;
			logmsg(LOG_INFO, "\n\tCHANGE_TO_EXCLUDE_MODE ");
			if (source_count == 0) logmsg(LOG_INFO, " EXCLUDE NULL => JOIN(ASM) ");
			break;
		case ALLOW_NEW_SOURCES:
			wattron(win_logs, COLOR_PAIR(GREEN_ON_BLACK));
			if (g->mode == 0)
				g->mode = FILTER_MODE_INCLUDE;
			logmsg(LOG_INFO, "\n\tALLOW_NEW_SOURCES mode=%i", g->mode);
			break;
		case BLOCK_OLD_SOURCES:
			wattron(win_logs, COLOR_PAIR(RED_ON_BLACK));
			if (g->mode == 0)
				g->mode = FILTER_MODE_EXCLUDE;
			logmsg(LOG_INFO, "\n\tBLOCK_OLD_SOURCES ");
			break;
		default:
			logmsg(LOG_INFO, "\n\t(UNKNOWN MODE) ");
			break;
	}
	wattron(win_logs, COLOR_PAIR(WHITE_ON_BLACK));

	inet_ntop(AF_INET6, addr.s6_addr, straddr, INET6_ADDRSTRLEN);
	logmsg(LOG_INFO, "\n\tmulticast group addr=%s", straddr);
	logmsg(LOG_INFO, " mode=%i", mrec->mar_type);
	logmsg(LOG_INFO, " auxlen=%i", mrec->mar_auxlen);
	logmsg(LOG_INFO, " sources=%i", source_count);

	/* loop through source addresses */
	src = &(mrec->mar_address); /* actually ptr to in6_addr *before* src */
	for (int i = 0; i < source_count; i++) {
		inet_ntop(AF_INET6, (++src)->s6_addr, straddr, INET6_ADDRSTRLEN);
		logmsg(LOG_INFO, "\n\t\tsource=%s", straddr);

		/* write source addresses */
		if (mrec->mar_type == BLOCK_OLD_SOURCES)
			del_source_record(g, src);
		else
			add_source_record(g, src);
	}

	/* show user what happened */
	display_update();

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
	struct sigaction sa = {};
	struct sigevent sev = {};
	char buf_recv[BUFSIZE];
	char buf_ctrl[BUFSIZE];
	char buf_name[BUFSIZE];
	uint16_t rec;

	while (--argc) {
		if (strcmp(argv[argc], "--noexpire") == 0) {
			opt_noexpire = 1;
		}
		else {
			fprintf(stderr, "unknown option '%s'\n", argv[argc]);
			exit(ERROR_UNKNOWN_OPTION);
		}
	}

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

	/* prepare timer and handler */
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = handle_timer;
	sigemptyset(&sa.sa_mask);
	sigaction(TIMER_SIG, &sa, NULL);
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = TIMER_SIG;
	timer_create(CLOCK_REALTIME, &sev, &tid);

	signal(SIGINT, handle_sigint);

	/* prepare display */
	display_init();

	/* initialize message */
	iov[0].iov_base = buf_recv;
	iov[0].iov_len = BUFSIZE;
	msg.msg_control = buf_ctrl;
	msg.msg_controllen = BUFSIZE;
	msg.msg_name = buf_name;
	msg.msg_namelen = BUFSIZE;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	for (;;) {
		if (timer_expiry) expire_records(); /* check timer before syscall */
		bytes = recvmsg(sock, &msg, 0);
		if (timer_expiry) { expire_records(); continue; } /* syscall interrupted */
		if (bytes < 0) {
			perror("recvmsg");
			if (errno == EINTR)
				continue;
			else {
				logmsg(LOG_INFO, "recvmsg error\n");
				break;
			}
		}
		else {
			icmp6 = (struct icmp6_hdr *) buf_recv;
			logmsg(LOG_INFO, "msg received (%i bytes)\ttype %i => ",
				(int)bytes, (int)icmp6->icmp6_type);
			switch (icmp6->icmp6_type) {
				case ND_ROUTER_SOLICIT:
					logmsg(LOG_INFO, "ND_ROUTER_SOLICIT");
					break;
				case ND_ROUTER_ADVERT:
					logmsg(LOG_INFO, "ND_ROUTER_ADVERT");
					break;
				case ND_NEIGHBOR_SOLICIT:
					logmsg(LOG_INFO, "ND_NEIGHBOR_SOLICIT");
					break;
				case ND_NEIGHBOR_ADVERT:
					logmsg(LOG_INFO, "ND_NEIGHBOR_ADVERT");
					break;
				case ND_REDIRECT:
					logmsg(LOG_INFO, "ND_REDIRECT");
					break;
				case MLD2_LISTEN_REPORT:
					logmsg(LOG_INFO, "MLD2_LISTEN_REPORT");

					ifidx = interface_index(msg);
					logmsg(LOG_INFO, " iface=%i", ifidx);

					/* number of mcast address records */
					rec = ntohs(icmp6->icmp6_data16[1]);
					logmsg(LOG_INFO, " (records=%i)", rec);

					/* process the Multicast Address Record(s) */
					mrec = (struct mar *)(buf_recv + MLD2_HEADER_SIZE);
					for (int i = 0; i < rec; i++) {

						/* don't read beyond end of packet */
						assert((void *)mrec <= (void *)(icmp6 + bytes));

						mrec = process_multicast_address_record(mrec, ifidx);
					}
					break;
				default:
					logmsg(LOG_INFO, "UNKNOWN");
					break;
			}
			logmsg(LOG_INFO, "\n");
		}
	}

	return 0;
}
