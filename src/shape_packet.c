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

#include "shape_packet.h"

libnet_t *
shape_packet()
{
#ifdef DEBUG
    fprintf(stdout, "DEBUG: shape_packet()\n");
#endif

    switch(injection_type)
    {
        case ETHERTYPE_IP:
#ifdef DEBUG
            fprintf(stdout, "DEBUG: Injecting IP traffic\n");
#endif
            switch(ip4hdr_o.p)
            {
                case IPPROTO_TCP:
                    if((pkt_d = shape_tcp_hdr(pkt_d)) == NULL)
                        return pkt_d;

                    break;

                case IPPROTO_UDP:
                    if((pkt_d = shape_udp_hdr(pkt_d)) == NULL)
                        return pkt_d;

                    break;

                case IPPROTO_ICMP:
                    if((pkt_d = shape_icmpv4_hdr(pkt_d)) == NULL)
                        return pkt_d;

                    break;
            }

            if((pkt_d = shape_ipv4_hdr(pkt_d)) == NULL)
                return pkt_d;

            break;

        case ETHERTYPE_ARP:
            if((pkt_d = shape_arp_hdr(pkt_d)) == NULL)
                return pkt_d;

            break;
    }

    if(ehdr_o.s_addr || ehdr_o.d_addr)
    {
        if((pkt_d = shape_ethernet_hdr(pkt_d)) == NULL)
            return pkt_d;
    }
    else
    if(injection_type == ETHERTYPE_ARP)
        if((pkt_d = shape_ethernet_hdr_auto(pkt_d)) == NULL)
            return pkt_d;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: End shape_packet()\n");
#endif

    return pkt_d;
}
