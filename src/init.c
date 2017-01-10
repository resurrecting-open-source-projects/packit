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

#include "init.h"

void
injection_struct_init()
{
    memset(&g_ehdr_o, 0, sizeof(struct enethdr_opts));
    g_ehdr_o.d_addr = NULL;
    g_ehdr_o.s_addr = NULL;

    memset(&g_ahdr_o, 0, sizeof(struct arphdr_opts));
    g_ahdr_o.op_type = ARPOP_REQUEST;
    g_ahdr_o.s_paddr = IPV4_DEFAULT;
    g_ahdr_o.s_eaddr = (u_int8_t *) ETH_DEFAULT;
    g_ahdr_o.r_paddr = IPV4_DEFAULT;
    g_ahdr_o.r_eaddr = (u_int8_t *) ETH_DEFAULT;

    memset(&g_ip4hdr_o, 0, sizeof(struct ip4hdr_opts));
    g_ip4hdr_o.ttl = (g_p_mode == M_INJECT) ? 128 : 1;
    g_ip4hdr_o.frag = 0;
    g_ip4hdr_o.tos = 0;
    g_ip4hdr_o.sum = 0;
    g_ip4hdr_o.id = 0;
    g_ip4hdr_o.rand_id = 1;

    memset(&g_thdr_o, 0, sizeof(struct tcphdr_opts));
    g_thdr_o.s_port = (u_int16_t)retrieve_rand_int(P_UINT16);
    g_thdr_o.d_port = 0;
    g_thdr_o.urg = 0;
    g_thdr_o.ack = 0;
    g_thdr_o.psh = 0;
    g_thdr_o.rst = 0;
    g_thdr_o.syn = 0;
    g_thdr_o.fin = 0;
    g_thdr_o.urp = 0;
    g_thdr_o.win = 65535;
    g_thdr_o.ackn = 0;
    g_thdr_o.seqn = 0;
    g_thdr_o.rand_seqn = 1;

    memset(&g_uhdr_o, 0, sizeof(struct udphdr_opts));
    g_uhdr_o.s_port = (u_int16_t)retrieve_rand_int(P_UINT16);
    g_uhdr_o.d_port = 0;
    g_uhdr_o.sum = 0;

    memset(&g_i4hdr_o, 0, sizeof(struct icmp4hdr_opts));
    g_i4hdr_o.type = 8;
    g_i4hdr_o.code = 0;
    g_i4hdr_o.id = (u_int16_t)retrieve_rand_int(P_UINT16);
    g_i4hdr_o.seqn = (u_int16_t)retrieve_rand_int(P_UINT16);
    g_i4hdr_o.rand_gw = 0;
    g_i4hdr_o.gw = NULL;
    g_i4hdr_o.orig_id = 0;
    g_i4hdr_o.rand_orig_id = 0;
    g_i4hdr_o.orig_tos = 0;
    g_i4hdr_o.orig_ttl = 128;
    g_i4hdr_o.orig_p = IPPROTO_UDP;
    g_i4hdr_o.orig_sum = 1;
    g_i4hdr_o.mask = NULL; ;
    g_i4hdr_o.orig_s_addr = NULL;
    g_i4hdr_o.rand_orig_s_addr = 0;
    g_i4hdr_o.orig_d_addr = NULL;
    g_i4hdr_o.rand_orig_d_addr = 0;
    g_i4hdr_o.orig_d_port = 0;
    g_i4hdr_o.rand_orig_d_port = 0;
    g_i4hdr_o.orig_s_port = 0;
    g_i4hdr_o.rand_orig_s_port = 0;
    g_i4hdr_o.otime = 0;
    g_i4hdr_o.rtime = 0;
    g_i4hdr_o.ttime = 0;

    return;
}
