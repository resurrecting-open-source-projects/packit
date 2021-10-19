/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2013      Mats Erik Andersson <gnu@gisladisker.se>
 * Copyright 2015      Joao Eriberto Mota Filho <eriberto@eriberto.pro.br>
 * Copyright 2017      Robert Krause <ruport@f00l.de>
 * Copyright 2017      Sharad B
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

#include <stdio.h>
#include <string.h>
#include "inject_defs.h"
#include "print_injection.h"
#include "utils.h"
#include "globals.h"

void print_injection_details()
{
	char *arp_t, *icmp_t, *icmp_c = NULL;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: print_injection() g_init_type: %d\n",
		g_init_type);
#endif
	if (g_injection_type == ETHERTYPE_IP) {
#ifdef DEBUG
		fprintf(stdout, "DEBUG: ETHERTYPE_IP\n");
#endif
		g_thdr_o.flags[0] = '\0';
		if (g_ip4hdr_o.p == IPPROTO_TCP && !g_rawip) {
			if (g_thdr_o.syn)
				strcat(g_thdr_o.flags, "S");
			if (g_thdr_o.ack)
				strcat(g_thdr_o.flags, "A");
			if (g_thdr_o.fin)
				strcat(g_thdr_o.flags, "F");
			if (g_thdr_o.rst)
				strcat(g_thdr_o.flags, "R");
			if (g_thdr_o.psh)
				strcat(g_thdr_o.flags, "P");
			if (g_thdr_o.urg)
				strcat(g_thdr_o.flags, "U");
			if (strlen(g_thdr_o.flags) < 1)
				strcpy(g_thdr_o.flags, "None");
			fprintf(stdout, "TCP header:  Src Port: %d  ",
				g_s_port);
			if (g_p_mode == M_INJECT_RESPONSE)
				fprintf(stdout, "Dst Port: %d  ", g_d_port);
			else
				fprintf(stdout, "Dst Port(s): %s  ",
					g_s_d_port);
			fprintf(stdout, "Flag(s): %s\n", g_thdr_o.flags);
			fprintf(stdout, "\t     Window: %d  ", g_thdr_o.win);
			if (g_thdr_o.seqn)
				fprintf(stdout, "Seqn: %u  ", g_thdr_o.seqn);
			if (g_thdr_o.ackn)
				fprintf(stdout, "Ackn: %u  ", g_thdr_o.ackn);
			if (g_thdr_o.urp)
				fprintf(stdout, "Urg: %d ", g_thdr_o.urp);
		} else if (g_ip4hdr_o.p == IPPROTO_UDP && !g_rawip) {
			fprintf(stdout,
				"UDP header:  Src Port: %d  Dst Port(s): %s",
				g_s_port, g_s_d_port);
		} else if (g_ip4hdr_o.p == IPPROTO_ICMP && !g_rawip) {
			icmp_t = retrieve_icmp_type(g_i4hdr_o.type);
			fprintf(stdout, "ICMP header: Type: %s(%d)  ", icmp_t,
				g_i4hdr_o.type);
			if (g_i4hdr_o.code > 0) {
				icmp_c =
				    retrieve_icmp_code(g_i4hdr_o.type,
						       g_i4hdr_o.code);
				fprintf(stdout, "Code: %s(%d) ", icmp_c,
					g_i4hdr_o.code);
			}
			switch (g_i4hdr_o.type) {
			case ICMP_ECHOREPLY:
			case ICMP_ECHO:
			case ICMP_TSTAMP:
				fprintf(stdout, "ID: %d  Seqn: %d  ",
					g_i4hdr_o.id, g_i4hdr_o.seqn);
				break;
			case ICMP_UNREACH:
			case ICMP_REDIRECT:
			case ICMP_TIMXCEED:
				fprintf(stdout, "\n\t     Original Datagram\n");
				if (g_i4hdr_o.orig_p == IPPROTO_UDP)
					fprintf(stdout,
						"\t     Protocol: UDP(%d)  ",
						g_i4hdr_o.orig_p);
				else if (g_i4hdr_o.orig_p == IPPROTO_TCP)
					fprintf(stdout,
						"\t     Protocol: TCP(%d)  ",
						g_i4hdr_o.orig_p);
				else if (g_i4hdr_o.orig_p == IPPROTO_ICMP)
					fprintf(stdout,
						"\t     Protocol: ICMP(%d)  ",
						g_i4hdr_o.orig_p);
				fprintf(stdout, "Src Port: %d  Dst port: %d\n",
					g_i4hdr_o.orig_s_port,
					g_i4hdr_o.orig_d_port);
				fprintf(stdout,
					"\t     Src Address: %s  Dst Address: %s\n",
					g_i4hdr_o.orig_s_addr,
					g_i4hdr_o.orig_d_addr);
				fprintf(stdout,
					"\t     TTL: %d  ID: %d  TOS: 0x%X",
					g_i4hdr_o.orig_ttl, g_i4hdr_o.orig_id,
					g_i4hdr_o.orig_tos);
				break;
			case ICMP_TSTAMPREPLY:
				fprintf(stdout, "ID: %d  Seqn: %d\n",
					g_i4hdr_o.id, g_i4hdr_o.seqn);
				fprintf(stdout,
					"\t     Original Timestamp: %d\n",
					g_i4hdr_o.otime);
				fprintf(stdout,
					"\t     Received Timestamp: %d\n",
					g_i4hdr_o.rtime);
				fprintf(stdout, "\t     Transmit Timestamp: %d",
					g_i4hdr_o.ttime);
				break;
			case ICMP_MASKREQ:
			case ICMP_MASKREPLY:
				fprintf(stdout, "ID: %d  Seqn: %d",
					g_i4hdr_o.id, g_i4hdr_o.seqn);
				if (g_i4hdr_o.mask != NULL)
					fprintf(stdout,
						"\n\t     Address Mask: %s",
						g_i4hdr_o.mask);
				break;
			}
		}
		if (!g_rawip)
			fprintf(stdout, "\n");
		fprintf(stdout,
			"IP header:   Src Address: %s  Dst Address: %s\n",
			g_ip4hdr_o.s_addr, g_ip4hdr_o.d_addr);
		fprintf(stdout, "\t     TTL: %d  ID: %d  TOS: 0x%X  Len: %d  ",
			g_ip4hdr_o.ttl, g_ip4hdr_o.id,
			(u_int8_t) g_ip4hdr_o.tos, g_hdr_len);
		if (g_rawip)
			fprintf(stdout, "IP Protocol: %d  ", g_ip4hdr_o.p);
		if (g_ip4hdr_o.frag == 0x4000)
			fprintf(stdout, "(DF)");
		if (g_ehdr_o.s_addr || g_ehdr_o.d_addr)
			fprintf(stdout,
				"\nEth header:  Src Address: %s  Dst Address: %s",
				g_ehdr_o.shw_addr, g_ehdr_o.dhw_addr);
	} else if (g_injection_type == ETHERTYPE_ARP
		   || g_injection_type == ETHERTYPE_REVARP) {
#ifdef DEBUG
		fprintf(stdout, "DEBUG: %s\n",
			(g_injection_type ==
			 ETHERTYPE_REVARP) ? "ETHERTYPE_REVARP" :
			"ETHERTYPE_ARP");
#endif
		arp_t = retrieve_arp_type(g_ahdr_o.op_type);
		fprintf(stdout, "%s header:  Type: %s(%d)\n",
			(g_injection_type == ETHERTYPE_REVARP) ? "RARP" : "ARP",
			arp_t, g_ahdr_o.op_type);
		fprintf(stdout,
			"     Sender:  Protocol Address: %s  Hardware Address: %.17s\n",
			g_ahdr_o.s_paddr, g_ahdr_o.shw_addr);
		fprintf(stdout,
			"     Target:  Protocol Address: %s  Hardware Address: %.17s\n",
			g_ahdr_o.r_paddr, g_ahdr_o.rhw_addr);
		if (g_ehdr_o.s_addr || g_ehdr_o.d_addr)
			fprintf(stdout,
				"Eth header:  Src Address: %s  Dst Address: %s",
				g_ehdr_o.shw_addr, g_ehdr_o.dhw_addr);
	}
	fprintf(stdout, "\n");
}
