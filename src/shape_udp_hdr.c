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

#include "shape_udp_hdr.h"

libnet_t *
shape_udp_hdr(libnet_t *g_pkt_d)
{
#ifdef DEBUG
    fprintf(stdout, "DEBUG: shape_udp_hdr()\n");
#endif

    g_hdr_len = UDP_H;
    g_ip4hdr_o.p = IPPROTO_UDP;

    if(g_rand_d_port)
        g_d_port = (u_int16_t)retrieve_rand_int(P_UINT16);

    if(g_rand_s_port)
        g_s_port = (u_int16_t)retrieve_rand_int(P_UINT16);

    // If packet length is provided, create a packet with a sequence
    // as g_payload
    if(g_pkt_len)
    {
        g_payload = generate_padding(g_hdr_len + IPV4_H, g_pkt_len);
        g_payload_len = strlen((char*)g_payload);
        g_pkt_len = 0;
    }

    if(libnet_build_udp(
        g_s_port,
        g_d_port,
        g_hdr_len + g_payload_len,
        0,
        g_payload,
        g_payload_len,
        g_pkt_d,
        0) == -1)
    {
        fatal_error("Unable to build UDP header: %s", libnet_geterror(g_pkt_d));
    }

    return g_pkt_d;
}
