/*
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2013      Mats Erik Andersson <gnu@gisladisker.se>
 * Copyright 2015      Joao Eriberto Mota Filho <eriberto@eriberto.pro.br>
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
 *
 */

#include "print_injection.h"

void
print_injection_details()
{
    u_int8_t *arp_t, *icmp_t, *icmp_c = NULL;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: print_injection() init_type: %d\n", init_type);
#endif

    if(injection_type == ETHERTYPE_IP)
    {
#ifdef DEBUG
        fprintf(stdout, "DEBUG: ETHERTYPE_IP\n");
#endif
	thdr_o.flags[0] = '\0';
		
        if(ip4hdr_o.p == IPPROTO_TCP && !rawip)
        {
            if(thdr_o.syn)
                strcat(thdr_o.flags, "S");

            if(thdr_o.ack)
                strcat(thdr_o.flags, "A");

            if(thdr_o.fin)
                strcat(thdr_o.flags, "F");

            if(thdr_o.rst)
                strcat(thdr_o.flags, "R");

            if(thdr_o.psh)
                strcat(thdr_o.flags, "P");

            if(thdr_o.urg)
                strcat(thdr_o.flags, "U");

            if(strlen(thdr_o.flags) < 1)
                strcpy(thdr_o.flags, "None");

	    fprintf(stdout, "TCP header:  Src Port: %d  ", s_port);
 
            if(p_mode == M_INJECT_RESPONSE)
                fprintf(stdout, "Dst Port: %d  ", d_port);
            else
                fprintf(stdout, "Dst Port(s): %s  ", s_d_port);

            fprintf(stdout, "Flag(s): %s\n", thdr_o.flags);

	    fprintf(stdout, "\t     Window: %d  ", thdr_o.win);

            if(thdr_o.seqn)
                fprintf(stdout, "Seqn: %u  ", thdr_o.seqn);

            if(thdr_o.ackn)
                fprintf(stdout, "Ackn: %u  ", thdr_o.ackn);

            if(thdr_o.urp)
                fprintf(stdout, "Urg: %d ", thdr_o.urp);
        }
        else
        if(ip4hdr_o.p == IPPROTO_UDP && !rawip)
        {
            fprintf(stdout, "UDP header:  Src Port: %d  Dst Port(s): %s",
                s_port,
                s_d_port);
        }
        else
        if(ip4hdr_o.p == IPPROTO_ICMP && !rawip)
        {
	    icmp_t = retrieve_icmp_type(i4hdr_o.type);

	    fprintf(stdout, "ICMP header: Type: %s(%d)  ", icmp_t, i4hdr_o.type);

	    if(i4hdr_o.code > 0)
	    {
                icmp_c = retrieve_icmp_code(i4hdr_o.type, i4hdr_o.code);

	        fprintf(stdout, "Code: %s(%d) ", icmp_c, i4hdr_o.code);
	    }

	    switch(i4hdr_o.type)
	    {
		case ICMP_ECHOREPLY: case ICMP_ECHO: case ICMP_TSTAMP: 
	            fprintf(stdout, "ID: %d  Seqn: %d  ", i4hdr_o.id, i4hdr_o.seqn); 
		    break;

		case ICMP_UNREACH: case ICMP_REDIRECT: case ICMP_TIMXCEED:
		    fprintf(stdout, "\n\t     Original Datagram\n");

		    if(i4hdr_o.orig_p == IPPROTO_UDP)
		        fprintf(stdout, "\t     Protocol: UDP(%d)  ", i4hdr_o.orig_p);
		    else
                    if(i4hdr_o.orig_p == IPPROTO_TCP)
			fprintf(stdout, "\t     Protocol: TCP(%d)  ", i4hdr_o.orig_p);
		    else
                    if(i4hdr_o.orig_p == IPPROTO_ICMP)
			fprintf(stdout, "\t     Protocol: ICMP(%d)  ", i4hdr_o.orig_p);

		    fprintf(stdout, "Src Port: %d  Dst port: %d\n", 
	                i4hdr_o.orig_s_port, i4hdr_o.orig_d_port);

		    fprintf(stdout, "\t     Src Address: %s  Dst Address: %s\n",
	                i4hdr_o.orig_s_addr, i4hdr_o.orig_d_addr);

	            fprintf(stdout, "\t     TTL: %d  ID: %d  TOS: 0x%X",
			i4hdr_o.orig_ttl, i4hdr_o.orig_id, i4hdr_o.orig_tos);

		    break;

		case ICMP_TSTAMPREPLY:
		    fprintf(stdout, "ID: %d  Seqn: %d\n", i4hdr_o.id, i4hdr_o.seqn);
	            fprintf(stdout, "\t     Original Timestamp: %d\n", i4hdr_o.otime);
		    fprintf(stdout, "\t     Received Timestamp: %d\n", i4hdr_o.rtime);
		    fprintf(stdout, "\t     Transmit Timestamp: %d", i4hdr_o.ttime);

                    break;

		case ICMP_MASKREQ: case ICMP_MASKREPLY:
		    fprintf(stdout, "ID: %d  Seqn: %d", i4hdr_o.id, i4hdr_o.seqn);

	            if(i4hdr_o.mask != NULL)
		        fprintf(stdout, "\n\t     Address Mask: %s", i4hdr_o.mask);

		    break;
            }
        }

        if(!rawip)
	    fprintf(stdout, "\n");

	fprintf(stdout, "IP header:   Src Address: %s  Dst Address: %s\n", 
	    ip4hdr_o.s_addr, ip4hdr_o.d_addr); 
	
	fprintf(stdout, "\t     TTL: %d  ID: %d  TOS: 0x%X  Len: %d  ", 
	    ip4hdr_o.ttl, ip4hdr_o.id, (u_int8_t)ip4hdr_o.tos, hdr_len);

        if(rawip)
            fprintf(stdout, "IP Protocol: %d  ", ip4hdr_o.p);

	if(ip4hdr_o.frag == 0x4000)
	    fprintf(stdout, "(DF)");

        if(ehdr_o.s_addr || ehdr_o.d_addr)
            fprintf(stdout, "\nEth header:  Src Address: %s  Dst Address: %s",
                ehdr_o.shw_addr,
                ehdr_o.dhw_addr);
    }
    else
    if(injection_type == ETHERTYPE_ARP
       || injection_type == ETHERTYPE_REVARP)
    {
#ifdef DEBUG
       fprintf(stdout, "DEBUG: %s\n",
               (injection_type == ETHERTYPE_REVARP) ? "ETHERTYPE_REVARP" : "ETHERTYPE_ARP");
#endif

	arp_t = retrieve_arp_type(ahdr_o.op_type);

       fprintf(stdout, "%s header:  Type: %s(%d)\n",
               (injection_type == ETHERTYPE_REVARP) ? "RARP" : "ARP",
               arp_t, ahdr_o.op_type);
	fprintf(stdout, "     Sender:  Protocol Address: %s  Hardware Address: %.17s\n",
	    ahdr_o.s_paddr,
	    ahdr_o.shw_addr); 
	
	fprintf(stdout, "     Target:  Protocol Address: %s  Hardware Address: %.17s\n",
	    ahdr_o.r_paddr,
	    ahdr_o.rhw_addr); 

        if(ehdr_o.s_addr || ehdr_o.d_addr)
            fprintf(stdout, "Eth header:  Src Address: %s  Dst Address: %s", 
	        ehdr_o.shw_addr,
	        ehdr_o.dhw_addr);
    }

    fprintf(stdout, "\n");

    return;
}
  
