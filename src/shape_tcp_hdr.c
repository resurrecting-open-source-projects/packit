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

#include "error.h"
#include "utils.h"
#include "inject_defs.h"
#include "shape_tcp_hdr.h"
#include "globals.h"

libnet_t *shape_tcp_hdr(libnet_t * g_pkt_d)
{
	int flags;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: shape_tcp_hdr()\n");
#endif
	g_ip4hdr_o.p = IPPROTO_TCP;
	g_hdr_len = TCP_H;
	if (g_rand_s_port)
		g_s_port = (u_int16_t) retrieve_rand_int(P_UINT16);
	if (g_rand_d_port)
		g_d_port = (u_int16_t) retrieve_rand_int(P_UINT16);
	if ((g_thdr_o.rand_seqn && g_thdr_o.syn) == 1)
		g_thdr_o.seqn = (u_int32_t) retrieve_rand_int(P_INT32);
	flags = retrieve_tcp_flags();

	// If packet length is provided, create a packet with a sequence
	// as g_payload
	if (g_pkt_len) {
		g_payload = generate_padding(g_hdr_len + IPV4_H, g_pkt_len);
		g_payload_len = strlen((char *)g_payload);
		g_pkt_len = 0;
	}
	if (libnet_build_tcp(g_s_port,
			     g_d_port,
			     g_thdr_o.seqn,
			     g_thdr_o.ackn,
			     flags,
			     g_thdr_o.win,
			     0,
			     g_thdr_o.urp,
			     g_hdr_len + g_payload_len,
			     g_payload, g_payload_len, g_pkt_d, 0) == -1) {
		fatal_error("Unable to build TCP header: %s",
			    libnet_geterror(g_pkt_d));
	}
	if (g_port_range)
		g_d_port++;
	return g_pkt_d;
}
