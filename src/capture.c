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

#include "../include/packit.h"
#include "../include/capture.h"
#include "../include/utils.h"
#include "../include/error.h"

void
process_packets(u_int8_t *user, struct pcap_pkthdr *pkthdr, u_int8_t *packet)
{
    struct libnet_ethernet_hdr *ehdr;
    struct libnet_ipv4_hdr *iphdr;

#ifdef DEBUG
    fprintf(stdout, "\nDEBUG: process_packets()\n");
#endif

    ehdr = malloc(sizeof(struct libnet_ethernet_hdr));
    memset(ehdr, 0, sizeof(struct libnet_ethernet_hdr));

    iphdr = malloc(sizeof(struct libnet_ipv4_hdr));
    memset(iphdr, 0, sizeof(struct libnet_ipv4_hdr));

    if(display)
    {
        ehdr = (struct libnet_ethernet_hdr *)(packet);

        if(ehdr->ether_type == htons(ETHERTYPE_IP))
        {
#ifdef DEBUG
            fprintf(stdout, "\nDEBUG: ether_type: ip\n");
#endif

            if(p_mode == M_CAPTURE)
                print_separator(1, 2, "PID %d", cap_cnt + 1);
            else if(p_mode == M_INJECT_RESPONSE)
                print_separator(1, 2, "RCV %d", inj_cnt);

            print_timestamp(pkthdr->ts);
	 
            iphdr = (struct libnet_ipv4_hdr *)(packet + hdr_len);

#ifdef DEBUG
	    fprintf(stdout, "\nDEBUG: ip_p: %d\n", iphdr->ip_p);
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
		
            if(dump_pkt)
                if(pkthdr->caplen > hdr_len)
                    print_packet_hexdump(packet + hdr_len, pkthdr->caplen - hdr_len);    
        }
        else if(ehdr->ether_type == htons(ETHERTYPE_ARP))
        {
#ifdef DEBUG
            fprintf(stdout, "\nDEBUG: ether_type: ARP\n");
#endif

            if(p_mode == M_CAPTURE)
                print_separator(1, 2, "PID %d", cap_cnt + 1);
            else if(p_mode == M_INJECT_RESPONSE)
                print_separator(1, 2, "RCV %d", inj_cnt);

            print_timestamp(pkthdr->ts);
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

void
start_packet_capture(u_int8_t *filter, u_int32_t cnt)
{
    u_int32_t d_link, localnet, netmask;
    pcap_dumper_t *p_dumper = NULL;

    struct bpf_program bpf;

#ifdef DEBUG
    fprintf(stdout, "\nDEBUG: start_packet_capture()\n");
#endif

    memset(&bpf, 0, sizeof(struct bpf_program));

    signal(SIGTERM, capture_clean_exit);
    signal(SIGINT, capture_clean_exit);
    signal(SIGQUIT, capture_clean_exit);
    signal(SIGHUP, capture_clean_exit);

    if(strlen(r_file) > 0)
    {
        if((pkt = pcap_open_offline(r_file, error_buf)) == NULL)
            fatal_error("Unable to open file: %s", error_buf); 
    }
    else
    {
        if(device == NULL)
            if((device = pcap_lookupdev(error_buf)) == NULL)
                fatal_error("Unable to lookup device: %s", error_buf);

        if((pkt = pcap_open_live(device, snap_len, 1, READ_TIMEOUT, error_buf)) == NULL)
            fatal_error("Unable to open device: %s", error_buf);
    }

    if(strlen(w_file) > 0)
    {
#ifdef DEBUG
        fprintf(stdout, "\nDEBUG: Writing to capture file: %s\n", w_file);
#endif

        if((p_dumper = pcap_dump_open(pkt, w_file)) == NULL)
            fatal_error("Unable to initialize packet capture: %s", pcap_geterr(pkt));

        display--;
    }

    if(pcap_lookupnet(device, &localnet, &netmask, error_buf) < 0)
	fprintf(stderr, "\nWarning: Unable to lookup network: %s\n", error_buf);

    if(pcap_compile(pkt, &bpf, filter, 0, netmask) < 0)
        fprintf(stderr, "\nWarning: Unable to compile packet filters: %s\n", pcap_geterr(pkt));

    if(pcap_setfilter(pkt, &bpf) < 0)
        fatal_error("Unable to set packet filters: %s", pcap_geterr(pkt));

#ifdef HAVE_FREECODE
    pcap_freecode(&bpf); 
#endif /* HAVE_FREECODE */

    if((d_link = pcap_datalink(pkt)) < 0)
        fatal_error("Unable to determine datalink type: %s", pcap_geterr(pkt));

    hdr_len = retrieve_datalink_hdr_len(d_link);

    fprintf(stdout, "Mode:  Packet Capture ");

    if(t_rst)
	fprintf(stdout, "[TCP Reset] ");
    else if(t_rst > 1)
	fprintf(stdout, "[UDP Reset] ");

    if(strlen(r_file) > 0)
        fprintf(stdout, "using file: %s ", r_file);
    else
        fprintf(stdout, "using device: %s ", device);

    if(filter)
        fprintf(stdout, "[%s]", filter);

    fprintf(stdout, "\n");

    if(pcap_loop(pkt, cnt, 
        (display == 1) ? (pcap_handler)process_packets : (pcap_handler)pcap_dump, 
        (display == 1) ? NULL : (u_int8_t *)p_dumper) < 0)
    {
        fatal_error("Unable to initialize pcap_loop: %s", pcap_geterr(pkt));
    }

    capture_clean_exit(SUCCESS);

    return;
}
