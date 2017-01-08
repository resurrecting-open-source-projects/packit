/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002 Darren Bounds <dbounds@intrusense.com>
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
 */

#include "shape_tcp_hdr.h"

libnet_t *
shape_tcp_hdr(libnet_t *pkt_d)
{
    int flags;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: shape_tcp_hdr()\n");
#endif

    ip4hdr_o.p = IPPROTO_TCP;
    hdr_len = TCP_H;

    if(rand_s_port)
        s_port = (u_int16_t)retrieve_rand_int(P_UINT16);

    if(rand_d_port)
        d_port = (u_int16_t)retrieve_rand_int(P_UINT16);

    if((thdr_o.rand_seqn && thdr_o.syn) == 1)
        thdr_o.seqn =  (u_int32_t)retrieve_rand_int(P_INT32);

    flags = retrieve_tcp_flags();

    // If packet length is provided, create a packet with a sequence
    // as payload
    if(pkt_len)
    {
        payload = generate_padding(hdr_len + IPV4_H, pkt_len);
        payload_len = strlen(payload);
        pkt_len = 0;
    }

    if(libnet_build_tcp(
        s_port,
        d_port,
        thdr_o.seqn,
        thdr_o.ackn,
        flags,
        thdr_o.win,
        0,
        thdr_o.urp,
        hdr_len + payload_len,
        payload,
        payload_len,
        pkt_d,
        0) == -1)
    {
        fatal_error("Unable to build TCP header: %s", libnet_geterror(pkt_d));
    }

    if(port_range)
        d_port++;

    return pkt_d;
}
