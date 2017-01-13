/*
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2017  Sharad B <sbirmi@users.noreply.github.com>
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

#include "shape_ipv6_hdr.h"

libnet_t *
shape_ipv6_hdr(libnet_t *pkt_d)
{
#ifdef DEBUG
    fprintf(stdout, "DEBUG: shape_ipv6_hdr()\n");
#endif

    if(g_ip6hdr_o.rand_src_addr)
    {
        rand_ip6addr(&g_ip6hdr_o.src);
    }
    else if(g_ip6hdr_o.src_str)
    {
        g_ip6hdr_o.src = libnet_name2addr6(pkt_d, g_ip6hdr_o.src_str, LIBNET_RESOLVE);
    }
    else
        fatal_error("No source address");

    if(g_ip6hdr_o.rand_dst_addr)
    {
        rand_ip6addr(&g_ip6hdr_o.dst);
    }
    else if(g_ip6hdr_o.dst_str)
    {
        g_ip6hdr_o.dst = libnet_name2addr6(pkt_d, g_ip6hdr_o.dst_str, LIBNET_RESOLVE);
    }
    else
        fatal_error("No destination address");

#ifdef DEBUG
    char debug_src_string[256] = "";
    char debug_dst_string[256] = "";
    libnet_addr2name6_r(g_ip6hdr_o.src, LIBNET_DONT_RESOLVE, debug_src_string, 256);
    libnet_addr2name6_r(g_ip6hdr_o.dst, LIBNET_DONT_RESOLVE, debug_dst_string, 256);
    fprintf(stdout, "DEBUG: source IP: %s  destination IP: %s\n",
            debug_src_string, debug_dst_string);
#endif

//    if(g_ip4hdr_o.rand_p)
//        g_ip4hdr_o.p = (u_int8_t)retrieve_rand_int(P_UINT8);
//
//    if(g_ip4hdr_o.rand_id)
//        g_ip4hdr_o.id = (u_int16_t)retrieve_rand_int(P_UINT16);

    g_hdr_len = g_hdr_len + g_payload_len;

    if(libnet_build_ipv6(
        g_ip6hdr_o.traffic_class,
        g_ip6hdr_o.flow_label,
        g_hdr_len,
        g_ip6hdr_o.next_header,
        g_ip6hdr_o.hop_limit,
        g_ip6hdr_o.src,
        g_ip6hdr_o.dst,
        NULL, 0,
        pkt_d,
        0) == -1)
    {
        fatal_error("Unable to build IP header: %s", libnet_geterror(pkt_d));
    }

    return pkt_d;
}
