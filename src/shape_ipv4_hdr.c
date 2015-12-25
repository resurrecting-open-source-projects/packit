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

#include "shape_ipv4_hdr.h"

libnet_t *
shape_ipv4_hdr(libnet_t *pkt_d)
{
#ifdef DEBUG
    fprintf(stdout, "DEBUG: shape_ipv4_hdr()\n");
#endif

    if(ip4hdr_o.rand_s_addr)
        ip4hdr_o.s_addr = retrieve_rand_ipv4_addr(ip4hdr_o.s_addr);

    if(ip4hdr_o.rand_d_addr)
	ip4hdr_o.d_addr = retrieve_rand_ipv4_addr(ip4hdr_o.d_addr);

    if(ip4hdr_o.s_addr == NULL)
    {
        if((ip4hdr_o.n_saddr = libnet_get_ipaddr4(pkt_d)) == -1)
            fatal_error("Unable to retreive local IP address: %s", libnet_geterror(pkt_d));

        ip4hdr_o.s_addr = libnet_addr2name4(ip4hdr_o.n_saddr, 1);
    }
    else
        if((ip4hdr_o.n_saddr = libnet_name2addr4(pkt_d, ip4hdr_o.s_addr, 1)) == -1)
            fatal_error("Invalid source IP address: %s", ip4hdr_o.s_addr);

    if(ip4hdr_o.d_addr == NULL)
        fatal_error("No destination IP address defined");
   
    if((ip4hdr_o.n_daddr = libnet_name2addr4(pkt_d, ip4hdr_o.d_addr, 1)) == -1)
        fatal_error("Invalid destination IP address: %s", ip4hdr_o.d_addr);

#ifdef DEBUG
    fprintf(stdout, "DEBUG: source IP: %s  destination IP: %s\n", ip4hdr_o.d_addr, ip4hdr_o.s_addr);
#endif

    if(ip4hdr_o.rand_p)
        ip4hdr_o.p = (u_int8_t)retrieve_rand_int(P_UINT8);

    if(ip4hdr_o.rand_id)
        ip4hdr_o.id = (u_int16_t)retrieve_rand_int(P_UINT16);

    if(rawip && pkt_len)
    {
        payload = generate_padding(hdr_len + IPV4_H, pkt_len);
        payload_len = strlen(payload);
        pkt_len = 0;
    }

    hdr_len = hdr_len + IPV4_H + payload_len;

    if(libnet_build_ipv4(
        hdr_len,
        ip4hdr_o.tos,
        ip4hdr_o.id,
        ip4hdr_o.frag,
        ip4hdr_o.ttl,
        ip4hdr_o.p,
        ip4hdr_o.sum,
        ip4hdr_o.n_saddr,
        ip4hdr_o.n_daddr,
        (rawip) ? payload : NULL,
        (rawip) ? payload_len : 0,
        pkt_d,
        0) == -1)
    {
        fatal_error("Unable to build IP header: %s", libnet_geterror(pkt_d));
    }

    return pkt_d;
}
