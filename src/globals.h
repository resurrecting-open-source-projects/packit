/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2007      Kumar Appaiah <akumar@ee.iitm.ac.in>
 * Copyright 2016      Robert Krause <ruport@f00l.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 *
 * packit official page at https://github.com/eribertomota/packit
 */

#ifndef __GLOBALS_H
#define __GLOBALS_H

#ifndef __HAVE_CONFIG_H
#define __HAVE_CONFIG_H
#include "../config.h"
#endif

#include <libnet.h>
#include <pcap.h>
#include <sys/types.h>
#include <pcap-bpf.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "utils.h"
#include "usage.h"
#include "error.h"
#include "exit.h"
#include "version.h"

#define IPV4_DEFAULT                    0x00000000		/* 0.0.0.0 */
#define IPV4_BROADCAST                  "255.255.255.255"
#define MASK_DEFAULT                    "255.255.255.0"
#define ETH_DEFAULT                     0x000000000000		/* 00:00:00:00:00:00 */
#define ETH_BROADCAST                   0xffffffffffff		/* ff:ff:ff:ff:ff:ff */

#define ARP_H            		0x1c    /* ARP header:          28 bytes */
#define DNS_H                 		0xc     /* DNS header base:     12 bytes */
#define ETH_H             		0xe     /* Etherner header:     14 bytes */
#define ICMPV4_H          		0x4     /* ICMP header base:     4 bytes */
#define ICMPV6_H           		0x08    /* ICMP6 header base:    8 bytes */
#define ICMPV4_ECHO_H       		0x8     /* ICMP_ECHO header:     8 bytes */
#define ICMPV4_MASK_H       		0xc     /* ICMP_MASK header:    12 bytes */
#define ICMPV4_UNREACH_H   		0x8     /* ICMP_UNREACH header:  8 bytes */
#define ICMPV4_TIMXCEED_H    		0x8     /* ICMP_TIMXCEED header: 8 bytes */
#define ICMPV4_REDIRECT_H    		0x8     /* ICMP_REDIRECT header: 8 bytes */
#define ICMPV4_TSTAMP_H      		0x14    /* ICMP_TIMESTAMP headr:20 bytes */
#define IPV4_H               		0x14    /* IP header:           20 bytes */
#define IPV6_H               		0x28    /* IPv6 header:         40 bytes */
#define TCP_H                		0x14    /* TCP header:          20 bytes */
#define UDP_H                		0x8     /* UDP header:           8 bytes */

#define ICMP_ECHOREPLY         		0       /* echo reply */
#define ICMP_UNREACH           		3       /* dest unreachable, codes: */
#define ICMP_SOURCEQUENCH      		4       /* packet lost, slow down */
#define ICMP_ECHO			8	/* echo request */
#define ICMP_ROUTERADVERT      		9       /* router advertisement */
#define ICMP_ROUTERSOLICIT     		10      /* router solicitation */
#define ICMP_TIMXCEED         		11      /* time exceeded, code: */
#define ICMP_PARAMPROB         		12      /* ip header bad */
#define ICMP_TSTAMP            		13      /* timestamp request */
#define ICMP_TSTAMPREPLY       		14      /* timestamp reply */
#define ICMP_IREQ              		15      /* information request */
#define ICMP_IREQREPLY         		16      /* information reply */
#define ICMP_MASKREQ           		17      /* address mask request */
#define ICMP_MASKREPLY         		18      /* address mask reply */
#define ICMP_TRACEROUTE			30	/* some misc traceroute type */

/* UNREACH codes */
#define ICMP_UNREACH_NET                0       /* bad net */
#define ICMP_UNREACH_HOST               1       /* bad host */
#define ICMP_UNREACH_PROTOCOL           2       /* bad protocol */
#define ICMP_UNREACH_PORT               3       /* bad port */
#define ICMP_UNREACH_NEEDFRAG           4       /* IP_DF caused drop */
#define ICMP_UNREACH_SRCFAIL            5       /* src route failed */
#define ICMP_UNREACH_NET_UNKNOWN        6       /* unknown net */
#define ICMP_UNREACH_HOST_UNKNOWN       7       /* unknown host */
#define ICMP_UNREACH_ISOLATED           8       /* src host isolated */
#define ICMP_UNREACH_NET_PROHIB         9       /* net denied */
#define ICMP_UNREACH_HOST_PROHIB        10      /* host denied */
#define ICMP_UNREACH_TOSNET             11      /* bad tos for net */
#define ICMP_UNREACH_TOSHOST            12      /* bad tos for host */
#define ICMP_UNREACH_FILTER_PROHIB      13      /* admin prohib */
#define ICMP_UNREACH_HOST_PRECEDENCE    14      /* host prec vio. */
#define ICMP_UNREACH_PRECEDENCE_CUTOFF  15      /* prec cutoff */
/* REDIRECT codes */
#define ICMP_REDIRECT_NET       	0       /* for network */
#define ICMP_REDIRECT_HOST      	1       /* for host */
#define ICMP_REDIRECT_TOSNET    	2       /* for tos and net */
#define ICMP_REDIRECT_TOSHOST   	3       /* for tos and host */
/* TIMEXCEED codes */
#define ICMP_TIMXCEED_INTRANS   	0       /* ttl==0 in transit */
#define ICMP_TIMXCEED_REASS     	1       /* ttl==0 in reass */
/* PARAMPROB code */
#define ICMP_PARAMPROB_OPTABSENT 	1       /* req. opt. absent */

#define ETHERTYPE_IP        		0x0800  /* internet protocol */
#define ETHERTYPE_ARP       		0x0806  /* addr. resolution protocol */
#define ETHERTYPE_REVARP    		0x8035  /* reverse addr. resolution protocol */

#define OPT_MAXLEN          		32

#define M_INJECT            		1
#define M_INJECT_RESPONSE   		2
#define M_INJECT_CONNECT		3
#define M_TRACE				4	
#define M_CAPTURE           		10
#define M_CAPTURE_RESET     		11

#define P_UINT8				0xFF
#define P_INT16            		0x7FFF
#define P_UINT16            		0xFFFF
#define P_INT32             		0x7FFFFFFF
#define P_UINT32            		0xFFFFFFFF
#define P_INT64                         0x7FFFFFFFFFFFFFFF
#define P_UINT64                        0xFFFFFFFFFFFFFFFF

char w_file[OPT_MAXLEN];
char r_file[OPT_MAXLEN];

pcap_t *g_pkt;
u_int8_t g_tr_fin;
char *g_filter;
char *g_device;
u_int16_t g_hdr_len;
u_int16_t g_pkt_len;
u_int16_t g_verbose;
u_int16_t g_resolve;
u_int16_t g_p_mode;
u_int64_t g_cnt;
u_int64_t g_inj_cnt;
u_int64_t g_cap_cnt;

#endif /* __GLOBALS_H */
