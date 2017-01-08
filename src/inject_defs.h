/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2013      Mats Erik Andersson <gnu@gisladisker.se>
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

#ifndef __INJECTION_STRUCTS_H
#define __INJECTION_STRUCTS_H

struct ip4hdr_opts
{
    u_int16_t p;                   /* protocol type */
    u_int16_t rand_p;
    u_int16_t tos;                 /* type of service */
    u_int16_t sum;                 /* checksum */
    u_int16_t ttl;                 /* time to live */
    u_int16_t rand_ttl;
    u_int16_t frag;                /* fragment option */
    u_int16_t id;                  /* id number */
    u_int16_t rand_id;

    u_int8_t *s_addr;                  /* src address string */
    u_int8_t *src_addr_o1;
    u_int8_t *src_addr_o2;
    u_int8_t *src_addr_o3;
    u_int8_t *src_addr_o4;
    u_int32_t n_saddr;             /* src address network byte order */
    u_int16_t rand_s_addr;

    u_int8_t *d_addr;                  /* dst address string */
    u_int8_t *dst_addr_o1;
    u_int8_t *dst_addr_o2;
    u_int8_t *dst_addr_o3;
    u_int8_t *dst_addr_o4;
    u_int32_t n_daddr;             /* dst address network byte order */
    u_int16_t rand_d_addr;
} ip4hdr_o;

struct tcphdr_opts
{
    u_int16_t s_port;              /* tcp source port */
    u_int16_t d_port;              /* tcp destination port */

    char flags[6];                 /* total number of possible flags */
    u_int16_t urg;                 /* tcp urg flag */
    u_int16_t ack;                 /* tcp ack flag */
    u_int16_t psh;                 /* tcp psh flag */
    u_int16_t rst;                 /* tcp rst flag */
    u_int16_t syn;                 /* tcp syn flag */
    u_int16_t fin;                 /* tcp fin flag */
    u_int16_t urp;                 /* tcp urg pointer */
    u_int16_t rand_urp;
    u_int32_t ackn;                /* tcp ack number */
    u_int32_t rand_ackn;           /* random acknowledgement number */
    u_int32_t seqn;                /* tcp seq number */
    u_int16_t rand_seqn;           /* random sequence number (default) */
    u_int16_t win;                 /* tcp window size */
    u_int16_t rand_win;            /* random tcp window size */

} thdr_o;

struct udphdr_opts
{
    u_int16_t s_port;              /* udp source port */
    u_int16_t d_port;              /* udp destination port */

    u_int16_t sum;                      /* udp checksum */
} uhdr_o;

struct icmp4hdr_opts
{
    u_int16_t type;                /* icmp4 type */
    u_int16_t code;                /* icmp4 code */

    u_int16_t id;                  /* icmp4 id number */
    u_int16_t rand_id;

    u_int16_t seqn;                /* icmp4 sequence number */
    u_int16_t rand_seqn;

    u_int8_t *gw;                       /* gateway redirect address */
    u_int16_t rand_gw;

    u_int16_t orig_id;             /* original id */
    u_int16_t rand_orig_id;        /* original id */

    u_int16_t orig_ttl;            /* original ttl */
    u_int16_t orig_tos;            /* original type of service */

    u_int16_t orig_sum;                 /* original checksum */
    u_int16_t orig_p;                   /* original protocol */

    u_int8_t *orig_s_addr;              /* original source address */
    u_int16_t rand_orig_s_addr;

    u_int16_t orig_s_port;         /* original source port */
    u_int16_t rand_orig_s_port;

    u_int8_t *orig_d_addr;              /* original destination address */
    u_int16_t rand_orig_d_addr;

    u_int16_t orig_d_port;         /* original destination port */
    u_int16_t rand_orig_d_port;

    u_int8_t *mask;                     /* icmp4 mask */

    u_int32_t otime;                    /* original timestamp */
    u_int32_t rtime;                    /* recieved timestamp */
    u_int32_t ttime;                    /* transmit timestamp */
} i4hdr_o;

struct enethdr_opts
{
    u_int16_t rand_s_addr;
    u_int16_t rand_d_addr;

    u_int8_t *s_addr;                   /* source ethernet address string */
    u_int8_t shw_addr[18];
    u_int8_t *d_addr;                   /* destination ethernet address string */
    u_int8_t dhw_addr[18];
} ehdr_o;

struct arphdr_opts
{
    u_int16_t op_type;                  /* arp operation */

    u_int8_t *s_paddr;                  /* sender protocol address */
    u_int16_t rand_s_paddr;

    u_int8_t *r_paddr;                  /* receiver protocol address */
    u_int16_t rand_r_paddr;

    u_int8_t *s_eaddr;                  /* sender ethernet address */
    u_int16_t rand_s_eaddr;

    u_int8_t *r_eaddr;                  /* receiver ethernet address */
    u_int16_t rand_r_eaddr;

    u_int8_t shw_addr[18];
    u_int8_t rhw_addr[18];
} ahdr_o;

libnet_t *pkt_d;

u_int16_t init_type;
u_int16_t rand_d_port;
u_int16_t rand_s_port;
u_int16_t s_port;
u_int16_t d_port;
u_int16_t port_range;
u_int16_t interval_sec;
u_int16_t interval_usec;
u_int16_t injection_type;
u_int16_t r_timeout;
u_int16_t burst_rate;
u_int16_t payload_len;
u_int8_t *payload;
u_int8_t hex_payload;
u_int8_t *s_d_port;
u_int8_t hwaddr_p[18];
u_int8_t rawip;

struct timeval bf_pcap;
struct timeval af_pcap;


#endif /* __INJECTION_STRUCTS_H */
