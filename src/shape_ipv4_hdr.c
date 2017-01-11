/*
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2015      Joao Eriberto Mota Filho <eriberto@eriberto.pro.br>
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
 *
 */

#include "shape_ipv4_hdr.h"

libnet_t *
shape_ipv4_hdr(libnet_t *g_pkt_d)
{
#ifdef DEBUG
    fprintf(stdout, "DEBUG: shape_ipv4_hdr()\n");
#endif

    if(g_ip4hdr_o.rand_s_addr)
        g_ip4hdr_o.s_addr = retrieve_rand_ipv4_addr(g_ip4hdr_o.s_addr);

    if(g_ip4hdr_o.rand_d_addr)
	g_ip4hdr_o.d_addr = retrieve_rand_ipv4_addr(g_ip4hdr_o.d_addr);

    if(g_ip4hdr_o.s_addr == NULL)
    {
        if((g_ip4hdr_o.n_saddr = libnet_get_ipaddr4(g_pkt_d)) == -1)
            fatal_error("Unable to retrieve local IP address: %s", libnet_geterror(g_pkt_d));

        g_ip4hdr_o.s_addr = (u_int8_t*)libnet_addr2name4(g_ip4hdr_o.n_saddr, 1);
    }
    else
        if((g_ip4hdr_o.n_saddr = libnet_name2addr4(g_pkt_d, (char*)g_ip4hdr_o.s_addr, 1)) == -1)
            fatal_error("Invalid source IP address: %s", g_ip4hdr_o.s_addr);

    if(g_ip4hdr_o.d_addr == NULL)
        fatal_error("No destination IP address defined");

    if((g_ip4hdr_o.n_daddr = libnet_name2addr4(g_pkt_d, (char*)g_ip4hdr_o.d_addr, 1)) == -1)
        fatal_error("Invalid destination IP address: %s", g_ip4hdr_o.d_addr);

#ifdef DEBUG
    fprintf(stdout, "DEBUG: source IP: %s  destination IP: %s\n", g_ip4hdr_o.d_addr, g_ip4hdr_o.s_addr);
#endif

    if(g_ip4hdr_o.rand_p)
        g_ip4hdr_o.p = (u_int8_t)retrieve_rand_int(P_UINT8);

    if(g_ip4hdr_o.rand_id)
        g_ip4hdr_o.id = (u_int16_t)retrieve_rand_int(P_UINT16);

    if(g_rawip && g_pkt_len)
    {
        g_payload = generate_padding(g_hdr_len + IPV4_H, g_pkt_len);
        g_payload_len = strlen((char*)g_payload);
        g_pkt_len = 0;
    }

    g_hdr_len = g_hdr_len + IPV4_H + g_payload_len;

    if(libnet_build_ipv4(
        g_hdr_len,
        g_ip4hdr_o.tos,
        g_ip4hdr_o.id,
        g_ip4hdr_o.frag,
        g_ip4hdr_o.ttl,
        g_ip4hdr_o.p,
        g_ip4hdr_o.sum,
        g_ip4hdr_o.n_saddr,
        g_ip4hdr_o.n_daddr,
        (g_rawip) ? g_payload : NULL,
        (g_rawip) ? g_payload_len : 0,
        g_pkt_d,
        0) == -1)
    {
        fatal_error("Unable to build IP header: %s", libnet_geterror(g_pkt_d));
    }

    return g_pkt_d;
}
