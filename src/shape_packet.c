/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2004      Dennis Vshivkov <walrus@amur.ru>
 * Copyright 2013      Mats Erik Andersson <gnu@gisladisker.se>
 * Copyright 2017      Sharad B
 * Copyright 2020      David Polverari <david.polverari@gmail.com>
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

#include "shape_packet.h"

libnet_t *
shape_packet()
{
#ifdef DEBUG
    fprintf(stdout, "DEBUG: shape_packet()\n");
#endif

    switch(g_injection_type)
    {
        case ETHERTYPE_IP:
#ifdef DEBUG
            fprintf(stdout, "DEBUG: Injecting IP traffic\n");
#endif
            switch(g_ip4hdr_o.p)
            {
                case IPPROTO_TCP:
                    if((g_pkt_d = shape_tcp_hdr(g_pkt_d)) == NULL)
                        return g_pkt_d;

                    break;

                case IPPROTO_UDP:
                    if((g_pkt_d = shape_udp_hdr(g_pkt_d)) == NULL)
                        return g_pkt_d;

                    break;

                case IPPROTO_ICMP:
                    if((g_pkt_d = shape_icmpv4_hdr(g_pkt_d)) == NULL)
                        return g_pkt_d;

                    break;
            }

            if((g_pkt_d = shape_ipv4_hdr(g_pkt_d)) == NULL)
                return g_pkt_d;

            break;

        case ETHERTYPE_ARP:
        case ETHERTYPE_REVARP:
            if((g_pkt_d = shape_arp_hdr(g_pkt_d)) == NULL)
                return g_pkt_d;

            break;
    }

    if(g_ehdr_o.s_addr || g_ehdr_o.d_addr || g_ehdr_o.dot1q_vlan_id_cpi_prio)
    {
        if((g_pkt_d = shape_ethernet_hdr(g_pkt_d)) == NULL)
            return g_pkt_d;
    }
    else
    if(g_injection_type == ETHERTYPE_ARP || g_injection_type == ETHERTYPE_REVARP)
        if((g_pkt_d = shape_ethernet_hdr_auto(g_pkt_d, g_injection_type)) == NULL)
            return g_pkt_d;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: End shape_packet()\n");
#endif

    return g_pkt_d;
}
