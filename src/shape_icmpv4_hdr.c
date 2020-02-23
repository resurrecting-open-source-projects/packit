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

#include "shape_icmpv4_hdr.h"

libnet_t *
shape_icmpv4_hdr(libnet_t *g_pkt_d)
{
    u_int8_t ih_payload[8];
    u_int32_t ih_payload_len = 8;
    u_int32_t ihn_gw, ihn_mask = 0;
    u_int32_t ihn_saddr, ihn_daddr;
    u_int32_t orig_hlen = IPV4_H + ICMPV4_H;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: shape_icmpv4_hdr(): type: %d  code: %d\n", g_i4hdr_o.type, g_i4hdr_o.code);
#endif

    g_ip4hdr_o.p = IPPROTO_ICMP;

    switch(g_i4hdr_o.type)
    {
        case ICMP_ECHOREPLY: case ICMP_ECHO: default:
#ifdef DEBUG
            fprintf(stdout, "DEBUG: Building ICMP echo header\n");
#endif

            if(g_i4hdr_o.rand_seqn)
                g_i4hdr_o.seqn = (u_int16_t)retrieve_rand_int(P_UINT16);

            if(g_i4hdr_o.rand_id)
                g_i4hdr_o.id = (u_int16_t)retrieve_rand_int(P_UINT16);

            g_hdr_len = ICMPV4_ECHO_H;

            if(g_pkt_len)
            {
                g_payload = generate_padding(g_hdr_len + IPV4_H, g_pkt_len);
                g_payload_len = strlen((char*)g_payload);
                g_pkt_len = 0;
            }

            if(libnet_build_icmpv4_echo(
	        g_i4hdr_o.type,
	        g_i4hdr_o.code,
	        0,
	        g_i4hdr_o.id,
	        g_i4hdr_o.seqn,
	        g_payload,
	        g_payload_len,
	        g_pkt_d,
	        0) == -1)
	    {
	        fatal_error("Unable to build ICMPv4 echo header: %s", libnet_geterror(g_pkt_d));
	    }

            break;

	case ICMP_UNREACH: case ICMP_REDIRECT: case ICMP_TIMXCEED:
            if(g_i4hdr_o.orig_p == IPPROTO_TCP)
	        orig_hlen = IPV4_H + TCP_H;
	    else
            if(g_i4hdr_o.orig_p == IPPROTO_UDP)
                orig_hlen = IPV4_H + UDP_H;
            else
            if(g_i4hdr_o.orig_p == IPPROTO_ICMP)
	        orig_hlen = IPV4_H + ICMPV4_H;

	    if(g_i4hdr_o.rand_orig_s_addr)
                g_i4hdr_o.orig_s_addr = retrieve_rand_ipv4_addr(g_i4hdr_o.orig_s_addr);

            if(g_i4hdr_o.rand_orig_d_addr)
		g_i4hdr_o.orig_d_addr = retrieve_rand_ipv4_addr(g_i4hdr_o.orig_d_addr);

            if(g_i4hdr_o.rand_orig_id)
                g_i4hdr_o.orig_id = (u_int16_t)retrieve_rand_int(P_UINT16);

            if(g_i4hdr_o.rand_orig_s_port)
                g_i4hdr_o.orig_s_port = (u_int16_t)retrieve_rand_int(P_UINT16);

            if(g_i4hdr_o.rand_orig_d_port)
                g_i4hdr_o.orig_d_port = (u_int16_t)retrieve_rand_int(P_UINT16);

            if(g_i4hdr_o.orig_s_addr == NULL)
	        fatal_error("No original source IP address defined");

	    if((ihn_saddr = libnet_name2addr4(g_pkt_d, (char*)g_i4hdr_o.orig_s_addr, 1)) == -1)
	        fatal_error("Invalid original source IP address: %s", g_i4hdr_o.orig_s_addr);

	    if(g_i4hdr_o.orig_d_addr == NULL)
	        fatal_error("No original destination IP address defined");

	    if((ihn_daddr = libnet_name2addr4(g_pkt_d, (char*)g_i4hdr_o.orig_d_addr, 1)) == -1)
	        fatal_error("Invalid original destination IP address: %s", g_i4hdr_o.orig_d_addr);

            ih_payload[0] = (g_i4hdr_o.orig_s_port >> 8) & 0xff;
	    ih_payload[1] = g_i4hdr_o.orig_s_port & 0xff;
	    ih_payload[2] = (g_i4hdr_o.orig_d_port >> 8) & 0xff;
	    ih_payload[3] = g_i4hdr_o.orig_d_port & 0xff;
	    ih_payload[4] = 0;
	    ih_payload[5] = 32;
	    ih_payload[6] = 0;
	    ih_payload[7] = 0;

            ih_payload_len = 8;

	    if(g_i4hdr_o.type == ICMP_UNREACH)
	    {
#ifdef DEBUG
                fprintf(stdout, "DEBUG: Building ICMP unreachable header\n");
#endif

                g_hdr_len = ICMPV4_UNREACH_H;

                if(g_pkt_len)
                {
                    g_payload = generate_padding(g_hdr_len + IPV4_H, g_pkt_len);
                    g_payload_len = strlen((char*)g_payload);
                    g_pkt_len = 0;
                }

                if(libnet_build_ipv4(
                    orig_hlen,
                    g_i4hdr_o.orig_tos,
                    g_i4hdr_o.orig_id,
                    0,
                    g_i4hdr_o.orig_ttl,
                    g_i4hdr_o.orig_p,
                    g_i4hdr_o.orig_sum,
                    ihn_saddr,
                    ihn_daddr,
                    ih_payload,
                    ih_payload_len,
                    g_pkt_d,
                    0) == -1)
                {
                    fatal_error("Unable to build original IP header: %s", libnet_geterror(g_pkt_d));
                }

                if(libnet_build_icmpv4_unreach(
                    g_i4hdr_o.type,
                    g_i4hdr_o.code,
                    0,
                    NULL,
                    0,
                    g_pkt_d,
                    0) == -1)
                {
                    fatal_error("Unable to build ICMPv4 unreach header: %s", libnet_geterror(g_pkt_d));
	        }
            }
	    else
            if(g_i4hdr_o.type == ICMP_REDIRECT)
	    {
#ifdef DEBUG
                fprintf(stdout, "DEBUG: Building ICMP redirect header\n");
#endif

                if(g_i4hdr_o.rand_gw)
	            g_i4hdr_o.gw = retrieve_rand_ipv4_addr(g_i4hdr_o.gw);

                if(g_i4hdr_o.gw == NULL)
	            fatal_error("No gateway IP address defined");

                if((ihn_gw = libnet_name2addr4(g_pkt_d, (char*)g_i4hdr_o.gw, 1)) == -1)
	            fatal_error("Invalid gateway IP address: %s", g_i4hdr_o.gw);

                g_hdr_len = ICMPV4_REDIRECT_H;

                if(g_pkt_len)
                {
                    g_payload = generate_padding(g_hdr_len + IPV4_H, g_pkt_len);
                    g_payload_len = strlen((char*)g_payload);
                    g_pkt_len = 0;
                }

                if(libnet_build_ipv4(
                    orig_hlen,
                    g_i4hdr_o.orig_tos,
                    g_i4hdr_o.orig_id,
                    0,
                    g_i4hdr_o.orig_ttl,
                    g_i4hdr_o.orig_p,
                    g_i4hdr_o.orig_sum,
                    ihn_saddr,
                    ihn_daddr,
                    ih_payload,
                    ih_payload_len,
                    g_pkt_d,
                    0) == -1)
                {
                    fatal_error("Unable to build original IP header: %s", libnet_geterror(g_pkt_d));
                }

 	        if(libnet_build_icmpv4_redirect(
	            g_i4hdr_o.type,
	            g_i4hdr_o.code,
	            0,
                    ihn_gw,
                    NULL,
                    0,
	            g_pkt_d,
	            0) == -1)
 	        {
	            fatal_error("Unable to build ICMPv4 redirect header: %s", libnet_geterror(g_pkt_d));
	        }
	    }
            else
            if(g_i4hdr_o.type == ICMP_TIMXCEED)
	    {
#ifdef DEBUG
                fprintf(stdout, "DEBUG: Building ICMP timelimit exceeded header\n");
#endif

                g_hdr_len = ICMPV4_TIMXCEED_H;

                if(g_pkt_len)
                {
                    g_payload = generate_padding(g_hdr_len + IPV4_H, g_pkt_len);
                    g_payload_len = strlen((char*)g_payload);
                    g_pkt_len = 0;
                }

                if(libnet_build_ipv4(
                    orig_hlen,
                    g_i4hdr_o.orig_tos,
                    g_i4hdr_o.orig_id,
                    0,
                    g_i4hdr_o.orig_ttl,
                    g_i4hdr_o.orig_p,
                    g_i4hdr_o.orig_sum,
                    ihn_saddr,
                    ihn_daddr,
                    ih_payload,
                    ih_payload_len,
                    g_pkt_d,
                    0) == -1)
                {
                    fatal_error("Unable to build original IP header: %s", libnet_geterror(g_pkt_d));
                }

                if(libnet_build_icmpv4_timeexceed(
                    g_i4hdr_o.type,
	            g_i4hdr_o.code,
                    0,
                    NULL,
                    0,
 	            g_pkt_d,
	            0) == -1)
	        {
	            fatal_error("Unable to build ICMPv4 timeexceed header: %s", libnet_geterror(g_pkt_d));
	        }
	    }

            break;

        case ICMP_TSTAMP: case ICMP_TSTAMPREPLY:
#ifdef DEBUG
            fprintf(stdout, "DEBUG: Building ICMP timestamp header\n");
#endif

            if(g_i4hdr_o.rand_seqn)
                g_i4hdr_o.seqn = (u_int16_t)retrieve_rand_int(P_UINT16);

            if(g_i4hdr_o.rand_id)
                g_i4hdr_o.id = (u_int16_t)retrieve_rand_int(P_UINT16);

            g_hdr_len = ICMPV4_TSTAMP_H;

            if(g_pkt_len)
            {
                g_payload = generate_padding(g_hdr_len + IPV4_H, g_pkt_len);
                g_payload_len = strlen((char*)g_payload);
                g_pkt_len = 0;
            }

            if(libnet_build_icmpv4_timestamp(
                g_i4hdr_o.type,
                g_i4hdr_o.code,
                0,
		g_i4hdr_o.id,
		g_i4hdr_o.seqn,
		g_i4hdr_o.otime,
		g_i4hdr_o.rtime,
		g_i4hdr_o.ttime,
		g_payload,
		g_payload_len,
		g_pkt_d,
		0) == -1)
	    {
		fatal_error("Unable to build ICMPv4 timestamp header: %s", libnet_geterror(g_pkt_d));
	    }
				
            break;

        case ICMP_MASKREQ: case ICMP_MASKREPLY:
#ifdef DEBUG
            fprintf(stdout, "DEBUG: Building ICMP mask header\n");
#endif

            if(g_i4hdr_o.rand_seqn)
                g_i4hdr_o.seqn = (u_int16_t)retrieve_rand_int(P_UINT16);

            if(g_i4hdr_o.rand_id)
                g_i4hdr_o.id = (u_int16_t)retrieve_rand_int(P_UINT16);

            if(g_i4hdr_o.mask != NULL)
                if((ihn_mask = libnet_name2addr4(g_pkt_d, (char*)g_i4hdr_o.mask, 1)) == -1)
	            fatal_error("Invalid mask address: %s", g_i4hdr_o.mask);

            g_hdr_len = ICMPV4_MASK_H;

            if(g_pkt_len)
            {
                g_payload = generate_padding(g_hdr_len + IPV4_H, g_pkt_len);
                g_payload_len = strlen((char*)g_payload);
                g_pkt_len = 0;
            }

	    if(libnet_build_icmpv4_mask(
	        g_i4hdr_o.type,
	        g_i4hdr_o.code,
	        (g_i4hdr_o.mask != NULL) ? ihn_mask : 0,
	        g_i4hdr_o.id,
	        g_i4hdr_o.seqn,
		ihn_mask,
	        g_payload,
	        g_payload_len,
	        g_pkt_d,
	        0) == -1)
	    {
	        fatal_error("Unable to build ICMPv4 mask header: %s", libnet_geterror(g_pkt_d));
	    }

            break;
    }

    return g_pkt_d;
}

