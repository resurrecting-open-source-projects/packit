/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2017 Robert Krause <ruport@f00l.de>
 * Copyright 2017 Sharad B
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
 * packit official page at https://github.com/resurrecting-open-source-projects/packit
 */

#include "print_ipv4_hdr.h"

void print_ipv4_hdr(struct libnet_ipv4_hdr *iphdr)
{
	char *s_addr, *d_addr;
	struct in_addr ip_src, ip_dst;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: print_ipv4_hdr()\n");
#endif
	s_addr = malloc(sizeof(s_addr));
	d_addr = malloc(sizeof(d_addr));
	memset(&ip_src, 0, sizeof(struct in_addr));
	memset(&ip_dst, 0, sizeof(struct in_addr));
	s_addr =
	    libnet_addr2name4(iphdr->ip_src.s_addr,
			      ((g_resolve == 1 || g_resolve == 3) ? 1 : 0));
	d_addr =
	    libnet_addr2name4(iphdr->ip_dst.s_addr,
			      ((g_resolve == 1 || g_resolve == 3) ? 1 : 0));
	fprintf(stdout, "IP header:   Src Address: %s  Dst Address: %s\n",
		s_addr, d_addr);
	fprintf(stdout, "\t     TTL: %d  ID: %d  TOS: 0x%X  Len: %d  ",
		iphdr->ip_ttl,
		ntohs(iphdr->ip_id), iphdr->ip_tos, ntohs(iphdr->ip_len));
	if (ntohs(iphdr->ip_off) & IP_DF)
		fprintf(stdout, "(DF)  ");
	fprintf(stdout, "\n");
}
