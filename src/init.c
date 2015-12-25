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

#include "init.h"

void
injection_struct_init()
{
    memset(&ehdr_o, 0, sizeof(struct enethdr_opts));
    ehdr_o.d_addr = NULL;
    ehdr_o.s_addr = NULL;

    memset(&ahdr_o, 0, sizeof(struct arphdr_opts));
    ahdr_o.op_type = ARPOP_REQUEST;
    ahdr_o.s_paddr = IPV4_DEFAULT;
    ahdr_o.s_eaddr = ETH_DEFAULT;
    ahdr_o.r_paddr = IPV4_DEFAULT;
    ahdr_o.r_eaddr = ETH_DEFAULT;

    memset(&ip4hdr_o, 0, sizeof(struct ip4hdr_opts));
    ip4hdr_o.ttl = (p_mode == M_INJECT) ? 128 : 1;
    ip4hdr_o.frag = 0;
    ip4hdr_o.tos = 0;
    ip4hdr_o.sum = 0;
    ip4hdr_o.id = 0;
    ip4hdr_o.rand_id = 1;

    memset(&thdr_o, 0, sizeof(struct tcphdr_opts));
    thdr_o.s_port = (u_int16_t)retrieve_rand_int(P_UINT16);
    thdr_o.d_port = 0;
    thdr_o.urg = 0;
    thdr_o.ack = 0;
    thdr_o.psh = 0;
    thdr_o.rst = 0;
    thdr_o.syn = 0;
    thdr_o.fin = 0;
    thdr_o.urp = 0;
    thdr_o.win = 65535;
    thdr_o.ackn = 0;
    thdr_o.seqn = 0;
    thdr_o.rand_seqn = 1;

    memset(&uhdr_o, 0, sizeof(struct udphdr_opts));
    uhdr_o.s_port = (u_int16_t)retrieve_rand_int(P_UINT16);
    uhdr_o.d_port = 0;
    uhdr_o.sum = 0;

    memset(&i4hdr_o, 0, sizeof(struct icmp4hdr_opts));
    i4hdr_o.type = 8;
    i4hdr_o.code = 0;
    i4hdr_o.id = (u_int16_t)retrieve_rand_int(P_UINT16);
    i4hdr_o.seqn = (u_int16_t)retrieve_rand_int(P_UINT16);
    i4hdr_o.rand_gw = 0;
    i4hdr_o.gw = NULL;
    i4hdr_o.orig_id = 0;
    i4hdr_o.rand_orig_id = 0;
    i4hdr_o.orig_tos = 0;
    i4hdr_o.orig_ttl = 128;
    i4hdr_o.orig_p = IPPROTO_UDP;
    i4hdr_o.orig_sum = 1;
    i4hdr_o.mask = NULL; ;
    i4hdr_o.orig_s_addr = NULL;
    i4hdr_o.rand_orig_s_addr = 0;
    i4hdr_o.orig_d_addr = NULL;
    i4hdr_o.rand_orig_d_addr = 0;
    i4hdr_o.orig_d_port = 0;
    i4hdr_o.rand_orig_d_port = 0;
    i4hdr_o.orig_s_port = 0;
    i4hdr_o.rand_orig_s_port = 0;
    i4hdr_o.otime = 0;
    i4hdr_o.rtime = 0;
    i4hdr_o.ttime = 0;

    return;
}
