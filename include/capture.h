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

#ifndef __CAPTURE_H
#define __CAPTURE_H

#define READ_TIMEOUT            	500
#define SNAPLEN_DEFAULT         	68

u_int16_t display;
u_int16_t link_layer;
u_int16_t dump_pkt;
u_int16_t resolve;
u_int16_t resolve_h;
u_int16_t resolve_p;
u_int16_t time_gmt;
u_int16_t t_rst;
u_int16_t snap_len;
u_int32_t pkt_rst;

char w_file[OPT_MAXLEN];
char r_file[OPT_MAXLEN];

void capture_clean_exit(int sig);
void capture_stats();
void process_packets(u_int8_t *user, struct pcap_pkthdr *pkthdr, u_int8_t *packet);
void print_timestamp(struct timeval ts);
void print_packet_hexdump(u_int8_t *packet, int hdr_len);
void print_arp_hdr(u_int8_t *packet);
void print_tcp_hdr(u_int8_t *packet);
void print_udp_hdr(u_int8_t *packet);
void print_icmpv4_hdr(u_int8_t *packet);
void print_ipv4_hdr(struct libnet_ipv4_hdr *iphdr);
void print_ethernet_hdr(struct libnet_ethernet_hdr *enet);
void start_packet_capture(u_int8_t *filter, u_int32_t cnt);

#endif /* __CAPTURE_H */
