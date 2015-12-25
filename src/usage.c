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
#include "../include/version.h"
#include "../include/error.h"

void
print_usage()
{
    fprintf(stdout, "usage: packit -m mode [-options] 'expression'\n\n");
    
    fprintf(stdout, "Mode:\n");
    fprintf(stdout, "  -m mode     Runtime mode ");

#ifdef WITH_INJECTION 
    fprintf(stdout, "(Default: injection)\n");
#else
#ifdef WITH_CAPTURE
    fprintf(stdout, "(Default: capture)\n");
#else
    fprintf(stdout, "(Default: none)\n");
#endif /* WITH_CAPTURE */
#endif /* WITH_INJECTION */ 
    
    fprintf(stdout, "\n");
    
#ifdef WITH_CAPTURE
    fprintf(stdout, "Packet capture:\n");
    fprintf(stdout, "  -c count    Number of packets to process\n"); 
    fprintf(stdout, "  -e          Display link-level data\n");
    fprintf(stdout, "  -G          Display time in GMT\n");
    fprintf(stdout, "  -i device   Select listening interface\n");
    fprintf(stdout, "  -n          Disable IP/host resolution\n");
    fprintf(stdout, "  -nn         Disable port/service resolution\n");
    fprintf(stdout, "  -nnn        Disable IP/host and port/service resolution\n");
    fprintf(stdout, "  -r file     Read data from file\n");
    fprintf(stdout, "  -s snaplen  Bytes of data to read from each packet (Default: 68)\n");
    fprintf(stdout, "  -v          Verbose packet capture\n");
    fprintf(stdout, "  -w file     Write data to file\n");
    fprintf(stdout, "  -X          Dump the packet in hex and ascii\n");
    fprintf(stdout, "\n");
#endif /* WITH_CAPTURE */
    
#ifdef WITH_INJECTION
    fprintf(stdout, "Packet injection:\n");
    fprintf(stdout, "  -t proto    Select protocol for injection (Default: TCP) \n");
    fprintf(stdout, "\n");
    
    fprintf(stdout, "TCP/UDP header options\n");
    fprintf(stdout, "  -a ack      Acknowledgement number\n");
    fprintf(stdout, "  -D port     Destination port (Range format: start:end)\n");
    fprintf(stdout, "  -F flags    Flags (format: -F UAPRSF)\n");
    fprintf(stdout, "  -q seq      Sequence number\n");
    fprintf(stdout, "  -S port     Source port (Default: Random)\n");
    fprintf(stdout, "  -u urg      Urgent pointer\n");	
    fprintf(stdout, "  -W size     Window size (Default: 1500)\n");
    fprintf(stdout, "\n"); 
    
    fprintf(stdout, "ICMPv4 header options\n");
    fprintf(stdout, "  General:\n");
    fprintf(stdout, "  -C code     Code (Default: 0)\n");
    fprintf(stdout, "  -K type     Type (Default: 8)\n");
    fprintf(stdout, "\n");

    fprintf(stdout, "  Echo(0) / Echo Reply(8):\n");
    fprintf(stdout, "  -N id       ID number\n");
    fprintf(stdout, "  -Q seq      Sequence number\n");
    fprintf(stdout, "\n");
    
    fprintf(stdout, "  Unreachable(3) / Redirect(5) / Time Exceeded(11):\n");
    fprintf(stdout, "  -g gateway  Redirect gateway host (ICMP Redirect only)\n");
    fprintf(stdout, "  -j address  Original source address\n");
    fprintf(stdout, "  -J port     Original source port\n");
    fprintf(stdout, "  -l address  Original destination address\n");
    fprintf(stdout, "  -L port     Original destination port\n"); 
    fprintf(stdout, "  -m ttl      Original time to live\n");
    fprintf(stdout, "  -M id       Original ID number\n");
    fprintf(stdout, "  -O tos      Original type of service\n");
    fprintf(stdout, "  -P proto    Original protocol (Default: UDP)\n");
    fprintf(stdout, "\n");

    fprintf(stdout, "  Mask Request(17) / Mask Reply(18):\n");
    fprintf(stdout, "  -N id       ID number\n");
    fprintf(stdout, "  -Q seq      Sequence number\n");
    fprintf(stdout, "  -G mask     Address mask\n");
    fprintf(stdout, "\n");
    
    fprintf(stdout, "  Timestamp Request(13) / Timestamp Reply(14):\n");
    fprintf(stdout, "  -N id       ID number\n");
    fprintf(stdout, "  -Q seq      Sequence number\n");
    fprintf(stdout, "  -y ts       Original timestamp\n");
    fprintf(stdout, "  -k ts       Recieved timestamp\n");
    fprintf(stdout, "  -z ts       Transmit timestamp\n");
    fprintf(stdout, "\n");
    
    fprintf(stdout, "IP header options\n");
    fprintf(stdout, "  -d address  Destination address\n");
    fprintf(stdout, "  -f          Don't fragment\n");
    fprintf(stdout, "  -n id       ID number\n");
    fprintf(stdout, "  -o tos      Type of service\n");
    fprintf(stdout, "  -s address  Source address\n");
    fprintf(stdout, "  -T ttl      Time to live (Default: 128)\n");
    fprintf(stdout, "\n"); 

#ifndef MACOS 
    fprintf(stdout, "ARP header options\n");
    fprintf(stdout, "  -A op       Operation type (Default: 1 (ARP request))\n");
    fprintf(stdout, "  -r address  Target protocol address\n");
    fprintf(stdout, "  -R hwaddr   Target hardware address\n");
    fprintf(stdout, "  -x address  Sender protocol address\n");
    fprintf(stdout, "  -X hwaddr   Sender hardware address\n");
    fprintf(stdout, "\n");
    
    fprintf(stdout, "Ethernet header options\n");
    fprintf(stdout, "  -e ethaddr  Source ethernet address\n");
    fprintf(stdout, "  -E ethaddr  Destination ethernet address\n");
    fprintf(stdout, "\n"); 
#endif /* MACOS */
    
    fprintf(stdout, "General options\n");
    fprintf(stdout, "  -b burst    Send 'burst' packets per interval (Default: 1, Max: 10000)\n");
    fprintf(stdout, "  -c count    Number of packets to inject (Default: 1)\n");
    fprintf(stdout, "  -h          Display remote host response\n");
    fprintf(stdout, "  -H seconds  Specify the timeout value for '-h' (Default: 1)\n");
    fprintf(stdout, "  -i device   Select injection interface\n");
    fprintf(stdout, "  -p payload  Payload\n");
    fprintf(stdout, "  -v          Verbose packet injection\n");
    fprintf(stdout, "  -w seconds  Interval between injecting each burst (Default: 1)\n");
    fprintf(stdout, "\n");
#endif /* WITH_INJECTION */ 
    
    fprintf(stdout, "Version: %s\n", P_VERSION); 
    fprintf(stdout, "Author:  %s\n", P_AUTHOR);
    fprintf(stdout, "Website: %s\n", P_SITE);
    fprintf(stdout, "\nSee the man page for more options, detailed descriptions and examples.\n\n");

    exit(SUCCESS);
}

