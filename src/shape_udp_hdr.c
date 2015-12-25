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

#include "shape_udp_hdr.h"

libnet_t *
shape_udp_hdr(libnet_t *pkt_d)
{
#ifdef DEBUG
    fprintf(stdout, "DEBUG: shape_udp_hdr()\n");
#endif

    hdr_len = UDP_H;
    ip4hdr_o.p = IPPROTO_UDP;

    if(rand_d_port)
        d_port = (u_int16_t)retrieve_rand_int(P_UINT16);

    if(rand_s_port)
        s_port = (u_int16_t)retrieve_rand_int(P_UINT16);

    if(pkt_len)
    {
        payload = generate_padding(hdr_len + IPV4_H, pkt_len);
        payload_len = strlen(payload);
        pkt_len = 0;
    }

    if(libnet_build_udp(
        s_port, 
        d_port, 
        hdr_len + payload_len, 
        0, 
        payload, 
        payload_len, 
        pkt_d, 
        0) == -1)
    {
        fatal_error("Unable to build UDP header: %s", libnet_geterror(pkt_d));
    }

    return pkt_d; 
}
