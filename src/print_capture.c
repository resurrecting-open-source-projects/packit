/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2013      Mats Erik Andersson <gnu@gisladisker.se>
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

#include "print_capture.h"

void
print_capture(struct pcap_pkthdr *pkthdr, u_int8_t *packet)
{
    struct libnet_ethernet_hdr *ehdr;
    struct libnet_ipv4_hdr *iphdr;
    struct libnet_icmpv4_hdr *tr_icmphdr;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: print_capture()\n");
#endif

    if(display)
    {
        ehdr = (struct libnet_ethernet_hdr *)(packet);

        if(ehdr->ether_type == htons(ETHERTYPE_IP))
        {
#ifdef DEBUG
            fprintf(stdout, "DEBUG: ether_type: ip\n");
#endif

            if(p_mode == M_CAPTURE)
                print_separator(1, 2, "PID %lld", (u_int64_t)cap_cnt + 1);
            else
            if(p_mode == M_INJECT_RESPONSE)
                print_separator(1, 2, "RCV %lld", (u_int64_t)inj_cnt);

            iphdr = (struct libnet_ipv4_hdr *)(packet + hdr_len);

            if(p_mode == M_TRACE && !verbose)
            {
                 print_ipv4_hdr(iphdr);

                 tr_icmphdr = (struct libnet_icmpv4_hdr *)(packet + IPV4_H + hdr_len);
                 if(tr_icmphdr->icmp_type != 11 || tr_icmphdr->icmp_code != 0)
                     tr_fin = 1;
            }
            else
            {
                if(p_mode != M_TRACE)
                    print_ts(pkthdr->ts);
                else
                if(iphdr->ip_p != IPPROTO_ICMP)
                    tr_fin = 1;

#ifdef DEBUG
	        fprintf(stdout, "DEBUG: ip_p: %d\n", iphdr->ip_p);
#endif

                switch(iphdr->ip_p)
                {
                    case IPPROTO_TCP:
                        print_tcp_hdr(packet);
                        break;

                    case IPPROTO_UDP:
                        print_udp_hdr(packet);
                        break;

                    case IPPROTO_ICMP:
                        print_icmpv4_hdr(packet);
                        break;
                }

                print_ipv4_hdr(iphdr);

                if(link_layer)
                    print_ethernet_hdr(ehdr);
		
                if(dump_pkt && pkthdr->caplen > hdr_len)
                    print_packet_hexdump(packet + hdr_len, pkthdr->caplen - hdr_len);
            }
        }
        else
        if(ehdr->ether_type == htons(ETHERTYPE_ARP)
           || ehdr->ether_type == htons(ETHERTYPE_REVARP))
        {
#ifdef DEBUG
            fprintf(stdout, "DEBUG: ether_type: %s\n",
                    (ehdr->ether_type == ETHERTYPE_REVARP) ? "RARP" : "ARP");
#endif

            if(p_mode == M_CAPTURE)
                print_separator(1, 2, "PID %lld", (u_int64_t)cap_cnt + 1);
            else
            if(p_mode == M_INJECT_RESPONSE)
                print_separator(1, 2, "RCV %lld", (u_int64_t)inj_cnt);

            print_ts(pkthdr->ts);
            print_arp_hdr(packet);
	    print_ethernet_hdr(ehdr);

            if(dump_pkt)
                if(pkthdr->caplen > hdr_len)
                    print_packet_hexdump(packet + hdr_len, pkthdr->caplen - hdr_len);
	}
    }

    cap_cnt++;

    return;
}
