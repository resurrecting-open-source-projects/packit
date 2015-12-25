/*
 * author: Darren Bounds <dbounds@intrusense.com>
 * copyright: Copyright (C) 2002 by Darren Bounds
 * license: This software is under GPL version 2 of license
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * packit official page at http://packit.sourceforge.net
 */

#ifndef __INJECT_H
#define __INJECT_H

#define BURST_MAX      			10000 
#define IPV4_DEFAULT   			"0.0.0.0"
#define IPV4_BROADCAST 			"255.255.255.255"
#define MASK_DEFAULT   			"255.255.255.0"
#define ETH_DEFAULT    			"0:0:0:0:0:0"
#define ETH_BROADCAST  			"ff:ff:ff:ff:ff:ff"

libnet_t *pkt_d;

unsigned short init_type;
unsigned short rand_d_port;
unsigned short rand_s_port;
unsigned short s_port;
unsigned short d_port;
unsigned short port_range;
unsigned short interval_sec;
unsigned short interval_usec;
u_int16_t injection_type;
u_int16_t r_timeout;
u_int16_t burst_rate;
u_int16_t payload_len;
u_int8_t *payload;
u_int8_t *s_d_port;
u_int8_t hwaddr_p[17];
u_int8_t t;

struct timeval bf_pcap;
struct timeval af_pcap;

struct ip4hdr_opts
{
    unsigned short p;			/* protocol type */
    unsigned short tos; 		/* type of service */
    unsigned short sum;         	/* checksum */
    unsigned short ttl;         	/* time to live */
    unsigned short frag;        	/* fragment option */
    unsigned short id;          	/* id number */
    unsigned short rand_id;

    u_int8_t *s_addr;            	/* src address string */
    u_int32_t n_saddr; 	        	/* src address network byte order */ 
    unsigned short rand_s_addr; 

    u_int8_t *d_addr;            	/* dst address string */
    u_int32_t n_daddr; 	        	/* dst address network byte order */
    unsigned short rand_d_addr;
} ip4hdr_o;

struct tcphdr_opts
{
    unsigned short s_port;		/* tcp source port */
    unsigned short d_port;		/* tcp destination port */

    u_int8_t flags[6];          	/* total number of possible flags */
    u_int16_t urg;			/* tcp urg flag */
    u_int16_t ack;			/* tcp ack flag */ 
    u_int16_t psh;			/* tcp psh flag */
    u_int16_t rst;			/* tcp rst flag */
    u_int16_t syn;			/* tcp syn flag */
    u_int16_t fin;			/* tcp fin flag */
    u_int16_t urp;			/* tcp urg pointer */
    u_int32_t ackn;			/* tcp ack number */
    u_int32_t seqn;			/* tcp seq number */
    unsigned short rand_seqn;   	/* random sequence number (default) */
    unsigned short win;         	/* tcp window size */

} thdr_o;

struct udphdr_opts
{
    unsigned short s_port;		/* udp source port */
    unsigned short d_port;		/* udp destination port */

    u_int16_t sum;               	/* udp checksum */
} uhdr_o;

struct icmp4hdr_opts
{
    unsigned short type;         	/* icmp4 type */
    unsigned short code;         	/* icmp4 code */ 

    unsigned short id;	         	/* icmp4 id number */ 
    unsigned short rand_id;

    unsigned short seqn;          	/* icmp4 sequence number */
    unsigned short rand_seqn;
    
    u_int8_t *gw;			/* gateway redirect address */
    unsigned short rand_gw;

    unsigned short orig_id;      	/* original id */ 
    unsigned short rand_orig_id; 	/* original id */

    unsigned short orig_ttl;	 	/* original ttl */
    unsigned short orig_tos;     	/* original type of service */

    u_int16_t orig_sum;	         	/* original checksum */
    u_int16_t orig_p;            	/* original protocol */

    u_int8_t *orig_s_addr;        	/* original source address */
    unsigned short rand_orig_s_addr;

    unsigned short orig_s_port;	 	/* original source port */    
    unsigned short rand_orig_s_port;

    u_int8_t *orig_d_addr;       	/* original destination address */
    unsigned short rand_orig_d_addr;

    unsigned short orig_d_port;  	/* original destination port */
    unsigned short rand_orig_d_port;   

    u_int8_t *mask;		 	/* icmp4 mask */

    u_int32_t otime;             	/* original timestamp */
    u_int32_t rtime;             	/* recieved timestamp */
    u_int32_t ttime;             	/* transmit timestamp */
} i4hdr_o;

struct enethdr_opts
{
    u_int16_t eh_rand_s_addr;
    u_int16_t eh_rand_d_addr;

    u_int8_t *s_addr;		 	/* source ethernet address string */
    u_int8_t shw_addr[17];
    u_int8_t *d_addr;   	 	/* destination ethernet address string */
    u_int8_t dhw_addr[17];
} ehdr_o; 

struct arphdr_opts
{
    u_int16_t op_type;              	/* arp operation */
    
    u_int8_t *s_paddr;              	/* sender protocol address */
    unsigned short rand_s_paddr;

    u_int8_t *r_paddr;              	/* receiver protocol address */
    unsigned short rand_r_paddr;

    u_int8_t *s_eaddr;              	/* sender ethernet address */
    unsigned short rand_s_eaddr;

    u_int8_t *r_eaddr;                  /* receiver ethernet address */
    unsigned short rand_r_eaddr;

    u_int8_t shw_addr[17];
    u_int8_t rhw_addr[17];
} ahdr_o;

void injection_stats();
void injection_clean_exit(int sig);
void inject_packet();
void capture_response(int sig);
void enter_packet_foundry();
void print_injection();
void with_response();
void without_response();
int parse_port_range(char *rangestr);
int format_ethernet_addr(char *ethstr, u_int8_t u_eaddr[6]);
int retrieve_tcp_flags();
libnet_t *shape_packet();
libnet_t *shape_ethernet_hdr(libnet_t *pkt_d);
libnet_t *shape_ethernet_hdr_auto(libnet_t *pkt_d);
libnet_t *shape_arp_hdr(libnet_t *pkt_d);
libnet_t *shape_ipv4_hdr(libnet_t *pkt_d);
libnet_t *shape_tcp_hdr(libnet_t *pkt_d);
libnet_t *shape_udp_hdr(libnet_t *pkt_d);
libnet_t *shape_icmpv4_hdr(libnet_t *pkt_d);
libnet_t *shape_dhcpv4_hdr(libnet_t *pkt_d);

int setnonblock(pcap_t *pt, int nonblock, char *errbuf);

#endif /* __INJECT_H */
