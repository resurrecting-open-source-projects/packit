/*
 * author: Darren Bounds <dbounds@intrusense.com>
 * copyright: Copyright (c) 2002 by Darren Bounds
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
#include "../include/inject.h"
#include "../include/capture.h"
#include "../include/utils.h"
#include "../include/error.h"
#include "../include/version.h"

int opt;
char *optarg;

void
parse_capture_options(int argc, char *argv[])
{
    p_mode = M_CAPTURE;
    cnt = 0;
    cap_cnt = 0;
    snap_len = SNAPLEN_DEFAULT; 
    t_rst = 0;
    resolve = 3;
    verbose = 0;
    display = 1;
    link_layer = 0;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: parse_capture_options()\n");
#endif 

    while((opt = getopt(argc, argv, "c:eGi:nNr:Rs:vw:xX")) != -1)
    {
        switch(opt)
        {
            case 'c':
                cnt = (u_int32_t)atoi(optarg);
                break;

            case 'e':
                link_layer = 1;
                break;

	    case 'G':
		time_gmt = 1;
		break;

            case 'i':
                if(!(device = strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);
		
                break;

            case 'w':
                strncpy(w_file, optarg, OPT_MAXLEN);
                break;

            case 'r':
                strncpy(r_file, optarg, OPT_MAXLEN);
                break;

            case 's':
		snap_len = (u_int16_t)atoi(optarg);
		break;

            case 'v':
                verbose = 1;
                break;

            case 'n':
                resolve--;
	        break;

	    case 'x': case 'X':
		dump_pkt = 1;
		break;
        }
    }

    start_packet_capture(argv[optind], cnt);

    return;
}

void
parse_inject_options(int argc, char *argv[])
{
    u_int8_t *opts = NULL;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: parse_inject_options()\n");
#endif

    if(getuid() != 0) fatal_error("Sorry, you're not root!");

    p_mode = M_INJECT;
    opterr = 0;
    cnt = 1;
    inj_cnt = 1;
    cap_cnt = 0;
    s_port = 0;
    rand_s_port = 1;
    s_d_port = "0";
    d_port = 0;
    rand_d_port = 0;
    r_timeout = 1;
    burst_rate = 1;
    hwaddr_p[17] = 0;
    init_type = 1;
    interval_sec = 1;
    interval_usec = 0;
    payload = NULL;
    payload_len = 0;
    hdr_len = 0;
    display = 1;
    verbose = 0;
    link_layer = 0;

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
    ip4hdr_o.ttl = 128;
    ip4hdr_o.frag = 0;
    ip4hdr_o.tos = 0;
    ip4hdr_o.sum = 0;
    ip4hdr_o.id = 0;
    ip4hdr_o.rand_id = 1;
    
    memset(&thdr_o, 0, sizeof(struct tcphdr_opts));
    thdr_o.s_port = (unsigned short)retrieve_rand_int(P_UINT16);
    thdr_o.d_port = 0;
    thdr_o.urg = 0;
    thdr_o.ack = 0;
    thdr_o.psh = 0;
    thdr_o.rst = 0;
    thdr_o.syn = 0;
    thdr_o.fin = 0;
    thdr_o.urp = 0;
    thdr_o.win = 1500;
    thdr_o.ackn = 0;
    thdr_o.seqn = 0;
    thdr_o.rand_seqn = 1;

    memset(&uhdr_o, 0, sizeof(struct udphdr_opts));
    uhdr_o.s_port = (unsigned short)retrieve_rand_int(P_UINT16);
    uhdr_o.d_port = 0;
    uhdr_o.sum = 0;
    
    memset(&i4hdr_o, 0, sizeof(struct icmp4hdr_opts));
    i4hdr_o.type = 8;
    i4hdr_o.code = 0;
    i4hdr_o.id = (unsigned short)retrieve_rand_int(P_UINT16);
    i4hdr_o.seqn = (unsigned short)retrieve_rand_int(P_UINT16);
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

    while((opt = getopt(argc, argv, "t:")) != -1)
    {
        switch(opt)
        {
            case 't':
		if(!strncasecmp(optarg, "TCP", 3))        
                {
#ifdef DEBUG
                    fprintf(stdout, "DEBUG: TCP injection\n");
#endif
                    ip4hdr_o.p = IPPROTO_TCP;
                    injection_type = ETHERTYPE_IP;
                    opts = "a:b:c:d:D:e:E:fF:hH:i:n:p:q:s:S:T:O:u:U:vw:W:";
                }  
                else if(!strncasecmp(optarg, "UDP", 3))   
                {
#ifdef DEBUG
                    fprintf(stdout, "DEBUG: UDP injection\n");
#endif
                    ip4hdr_o.p = IPPROTO_UDP;
                    injection_type = ETHERTYPE_IP;
                    opts = "b:c:d:D:e:E:fhH:i:n:O:p:s:S:T:U:vw:";
                }
                else if(!strncasecmp(optarg, "ICMP", 4))  
                { 
#ifdef DEBUG
                    fprintf(stdout, "DEBUG: ICMP injection\n");
#endif
                    ip4hdr_o.p = IPPROTO_ICMP;
                    injection_type = ETHERTYPE_IP;
                    opts = "b:c:C:d:e:E:fg:G:hH:i:j:J:k:K:l:L:m:M:n:N:o:O:p:P:s:Q:t:T:U:vw:y:z:"; 
                }
		else if(!strncasecmp(optarg, "ARP", 3))    
                { 
#ifdef DEBUG
                    fprintf(stdout, "DEBUG: ARP injection\n");
#endif
#ifdef MACOS
                    fprintf(stderr, "\nError: ARP injection is not yet supported on this OS platform.\n");
                    exit(FAILURE);
#endif
                    injection_type = ETHERTYPE_ARP;
                    opts = "A:b:c:r:R:e:E:i:o:p:s:S:U:vx:X:";
                }
                else if(!strncasecmp(optarg, "RAWIP", 3)) 
                { 
#ifdef DEBUG
                    fprintf(stdout, "DEBUG: raw IP injection\n");
#endif
                    ip4hdr_o.p = IPPROTO_RAW;
                    injection_type = ETHERTYPE_IP;
                    opts = "b:c:d:e:E:f:i:n:O:p:s:T:U:vw:";
                }
                else 
                {
                    print_usage();
                }

                goto parse_inject;

                break;

            default:
                optind--;

                ip4hdr_o.p = IPPROTO_TCP;
                injection_type = ETHERTYPE_IP;
                opts = "a:b:c:d:D:e:E:fF:hH:i:n:p:q:s:S:T:O:u:U:vw:W:";

                goto parse_inject;

                break;
        }
    }

parse_inject:
#ifdef DEBUG
    fprintf(stdout, "DEBUG: parse_inject\n");
#endif

    while((opt = getopt(argc, argv, opts)) != -1)
    {
        switch(opt)
        {
            case 'a':
                thdr_o.ackn = (u_int32_t)atoi(optarg);
                break;

            case 'A':
                ahdr_o.op_type = (unsigned short)atoi(optarg);
                break;

            case 'b':
                burst_rate = (int)atoi(optarg);

		if(burst_rate > BURST_MAX || burst_rate < 1)
		    fatal_error("Invalid burst rate");
		
                break;

            case 'c':
                cnt = (u_int32_t)atoi(optarg);
                break;

            case 'C':
                i4hdr_o.code = (u_int16_t)atoi(optarg);
                break;

            case 'd':
		if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    ip4hdr_o.rand_d_addr = 1;
                
		if(!(ip4hdr_o.d_addr = strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'D':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    rand_d_port = 1;

                if(!(s_d_port = strdup(optarg)) && !rand_d_port)
		    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'e':
#ifdef MACOS
            fprintf(stderr, "\nWarning: You cannot specify an ethernet address on this operating system.\n");
	    break;
#endif
		if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    ehdr_o.eh_rand_s_addr = 1;

      		if(!(ehdr_o.s_addr = strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);

                init_type = 0;
                link_layer = 1;
                break;

            case 'E':
#ifdef MACOS
                fprintf(stderr, "\nWarning: You cannot specify an ethernet address on this operating system.\n");
		break;
#endif
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    ehdr_o.eh_rand_d_addr = 1;

                if(!(ehdr_o.d_addr = strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);

                init_type = 0;
                link_layer = 1;
                break;

	    case 'f':
		ip4hdr_o.frag = 0x4000;
		break;

            case 'F':
                if(strrchr(optarg, 'U'))
                    thdr_o.urg = 1;

                if(strrchr(optarg, 'A'))
                    thdr_o.ack = 1;

                if(strrchr(optarg, 'P'))
                    thdr_o.psh = 1;

                if(strrchr(optarg, 'R'))
                    thdr_o.rst = 1;

                if(strrchr(optarg, 'S'))
                    thdr_o.syn = 1;

                if(strrchr(optarg, 'F'))
                    thdr_o.fin = 1;

                break;

            case 'g':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    i4hdr_o.rand_gw = 1;

                if(!(i4hdr_o.gw = strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'G':
                if(!(i4hdr_o.mask = strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

	    case 'h':
	        p_mode = M_INJECT_RESPONSE;	
		break;

            case 'H':
                r_timeout = (unsigned short)atoi(optarg);
                break;

            case 'i':
                if(!(device = strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'j':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    i4hdr_o.rand_orig_s_addr = 1;

                if(!(i4hdr_o.orig_s_addr = strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'J':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    i4hdr_o.rand_orig_s_port = 1;
                else
                    i4hdr_o.orig_s_port = (unsigned short)atoi(optarg);

                break;

            case 'k':
                i4hdr_o.rtime = (unsigned long)atoi(optarg);
                break;

            case 'K':
                i4hdr_o.type = (u_int16_t)atoi(optarg);
                break;

            case 'l':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    i4hdr_o.rand_orig_d_addr = 1;

                if(!(i4hdr_o.orig_d_addr = strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'L':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    i4hdr_o.rand_orig_d_port = 1;
                else
                    i4hdr_o.orig_d_port = (unsigned short)atoi(optarg);

                break;

            case 'm':
                i4hdr_o.orig_ttl = (unsigned short)atoi(optarg);
                break;

            case 'M':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    i4hdr_o.rand_orig_id = 1;

                i4hdr_o.orig_id = (unsigned short)atoi(optarg);
                break;

            case 'n':
                ip4hdr_o.id = (unsigned short)atoi(optarg);
                ip4hdr_o.rand_id = 0;
                break;

            case 'N':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    i4hdr_o.rand_id = 1;

                i4hdr_o.id = (unsigned short)atoi(optarg);
                break;

            case 'o':
                ip4hdr_o.tos = (unsigned short)atoi(optarg);
                break;

            case 'O':
                i4hdr_o.orig_tos = (unsigned short)atoi(optarg);
                break;

            case 'p':
                if(!(payload = strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'P':
                if(!strcasecmp(optarg, "UDP"))
                    i4hdr_o.orig_p = 17;
                else if(!strncasecmp(optarg, "TCP", 3))
                    i4hdr_o.orig_p = 6;
                else if(!strncasecmp(optarg, "ICMP", 4))
                    i4hdr_o.orig_p = 1;
                else
                    fatal_error("Unknown ICMP original protocol: %s", optarg);

                break;

            case 'q':
                thdr_o.seqn = (u_int32_t)atoi(optarg);
                thdr_o.rand_seqn = 0;
                break;

            case 'Q':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    i4hdr_o.rand_seqn = 1;

                i4hdr_o.seqn = (unsigned short)atoi(optarg);
                break;

            case 'r':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    ahdr_o.rand_r_paddr = 1;

                if(!(ahdr_o.r_paddr = strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'R':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    ahdr_o.rand_r_eaddr = 1;

                if(!(ahdr_o.r_eaddr = strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 's':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    ip4hdr_o.rand_s_addr = 1;

                if(!(ip4hdr_o.s_addr = strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);
		
                break;

            case 'S':
                s_port = (unsigned short)atoi(optarg);
                rand_s_port = 0;
                break;

            case 'T':
                if(atoi(optarg) > 0xFF)
                    fatal_error("Invalid TTL value: %s", optarg);
                else
                    ip4hdr_o.ttl = (unsigned short)atoi(optarg);

                break;

            case 'u':
                thdr_o.urp = (int)atoi(optarg);
                break;
 
            case 'v':
                verbose = 1;
                break;

            case 'w':
                interval_sec = (unsigned short)atoi(optarg);
                break;

            case 'W':
                thdr_o.win = (unsigned short)atoi(optarg);
                break;

            case 'x':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    ahdr_o.rand_s_paddr = 1;

                if(!(ahdr_o.s_paddr = strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'X':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    ahdr_o.rand_s_eaddr = 1;

                if(!(ahdr_o.s_eaddr = strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

            case 'y':
                i4hdr_o.otime = (unsigned long)atoi(optarg);
                break;

            case 'z':
                i4hdr_o.ttime = (unsigned long)atoi(optarg);
                break;
        }
    }

    enter_packet_foundry();

    return;
}

int
main(int argc, char *argv[])
{
    if(argc < 2) print_usage();
    
    opterr = 0;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: main()\n");
#endif

    while((opt = getopt(argc, argv, "m:")) != -1)
    {
        opterr = 1;

        switch(opt)
        {
            case 'm':
#ifdef WITH_CAPTURE
                if(!strncasecmp(optarg, "CAPTURE", 7) || !strncasecmp(optarg, "c", 1))
                    parse_capture_options(argc, argv);
#endif
#ifdef WITH_INJECTION
                if(!strncasecmp(optarg, "INJECT", 6) || !strncasecmp(optarg, "i", 1))
                    parse_inject_options(argc, argv);
#endif
		
                fprintf(stderr, "\nError: Invalid runtime mode\n");
                print_usage();
 
                break;
            default: 
                optind--;
#ifdef WITH_INJECTION
		parse_inject_options(argc, argv);
		break;
#endif
#ifdef WITH_CAPTURE
		parse_capture_options(argc, argv);
		break;
#endif

		fprintf(stderr, "\nError: Packit was built with neither capture nor injection support!\n");
                break;
        }
    }

    /* Never gets here */
    exit(SUCCESS);
}        
