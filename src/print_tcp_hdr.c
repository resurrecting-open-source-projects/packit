/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2017 Robert Krause <ruport@f00l.de>
 * Copyright 2017 Sharad B
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#include "print_tcp_hdr.h"

void print_tcp_hdr(u_int8_t * packet)
{
	char flags[7];

	struct libnet_tcp_hdr *tcphdr;
	struct servent *port_src, *port_dst;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: print_tcp_hdr()\n");
#endif
	port_src = malloc(sizeof(struct servent));
	port_dst = malloc(sizeof(struct servent));
	memset(port_src, 0, sizeof(struct servent));
	memset(port_dst, 0, sizeof(struct servent));
	memset(flags, 0, sizeof(flags));
	tcphdr = (struct libnet_tcp_hdr *)(packet + IPV4_H + g_hdr_len);
	if (tcphdr->th_flags & TH_URG)
		strcat(flags, "U");
	if (tcphdr->th_flags & TH_ACK)
		strcat(flags, "A");
	if (tcphdr->th_flags & TH_PUSH)
		strcat(flags, "P");
	if (tcphdr->th_flags & TH_RST)
		strcat(flags, "R");
	if (tcphdr->th_flags & TH_SYN)
		strcat(flags, "S");
	if (tcphdr->th_flags & TH_FIN)
		strcat(flags, "F");
	if (strlen(flags) == 0)
		strcpy(flags, "None");
	fprintf(stdout,
		"TCP header:  Src Port: %d  Dst Port: %d  Flag(s): %s\n",
		htons(tcphdr->th_sport), htons(tcphdr->th_dport), flags);
	fprintf(stdout, "\t     Window: %d  ", htons(tcphdr->th_win));
	if (tcphdr->th_seq > 0)
		fprintf(stdout, "Seqn: %lu  ", (u_long) ntohl(tcphdr->th_seq));
	if (tcphdr->th_ack > 0)
		fprintf(stdout, "Ackn: %lu  ", (u_long) ntohl(tcphdr->th_ack));
	if (tcphdr->th_urp)
		fprintf(stdout, "Urg: %d  ", ntohs(tcphdr->th_urp));
	fprintf(stdout, "\n");
}
