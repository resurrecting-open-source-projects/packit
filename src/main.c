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

#include "main.h"

void
parse_capture_options(int argc, char *argv[])
{
    p_mode = M_CAPTURE;
    cnt = 0;
    cap_cnt = 0;
    snap_len = SNAPLEN_DEFAULT; 
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
                cnt = (u_int64_t)atoi(optarg);
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

    capture_init(argv[optind], cnt);

    return;
}

void
parse_inject_options(int argc, char *argv[], u_int16_t iopt)
{
    u_int8_t *opts = NULL;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: parse_inject_options(%d)\n", p_mode);
#endif

    if(getuid() != 0) fatal_error("Sorry, you're not root!");

    p_mode = iopt;

    define_injection_defaults();
    injection_struct_init();

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
                    opts = "a:b:c:d:D:e:E:fF:hH:i:n:p:q:Rs:S:T:o:u:vw:W:Z:";
                }  
                else 
                if(!strncasecmp(optarg, "UDP", 3))   
                {
#ifdef DEBUG
                    fprintf(stdout, "DEBUG: UDP injection\n");
#endif
                    ip4hdr_o.p = IPPROTO_UDP;
                    injection_type = ETHERTYPE_IP;
                    opts = "b:c:d:D:e:E:fhH:i:n:o:p:Rs:S:T:vw:Z:";
                }
                else
                if(!strncasecmp(optarg, "ICMP", 4))  
                { 
#ifdef DEBUG
                    fprintf(stdout, "DEBUG: ICMP injection\n");
#endif
                    ip4hdr_o.p = IPPROTO_ICMP;
                    injection_type = ETHERTYPE_IP;
                    opts = "b:c:C:d:e:E:fg:G:hH:i:j:J:k:K:l:L:m:M:n:N:o:O:p:P:Q:Rs:t:T:U:vw:z:Z:"; 
                }
		else
                if(!strncasecmp(optarg, "ARP", 3))    
                { 
                    if(p_mode == M_TRACE) 
                        fatal_error("ARP is not supported with trace mode.");
#ifdef DEBUG
                    fprintf(stdout, "DEBUG: ARP injection\n");
#endif
#ifdef MACOS
                    fprintf(stderr, "\nError: ARP injection is not yet supported on this OS platform.\n");
                    exit(FAILURE);
#endif
                    injection_type = ETHERTYPE_ARP;
                    init_type = 0;
                    opts = "A:b:c:e:E:i:p:Rs:S:vx:X:y:Y:";
                }
                else
                if(!strncasecmp(optarg, "RAWIP", 3)) 
                { 
                    if(p_mode == M_TRACE)
                        fatal_error("RAW is not supported with trace mode.");
#ifdef DEBUG
                    fprintf(stdout, "DEBUG: raw IP injection\n");
#endif
                    rawip = ip4hdr_o.p = IPPROTO_RAW;
                    injection_type = ETHERTYPE_IP;
                    opts = "b:c:d:e:E:f:i:n:o:p:Rs:T:U:vV:w:Z:";
                }
                else 
                    print_usage();

                goto parse_inject;

                break;

            default:
                if(optind > 1) optind--;
                injection_type = ETHERTYPE_IP;

                if(p_mode == M_TRACE)
                {
                    ip4hdr_o.p = IPPROTO_ICMP;
                    opts = "b:c:C:d:e:E:fg:G:hH:i:j:J:k:K:l:L:m:M:n:N:o:O:p:P:Q:Rs:t:T:U:vw:z:Z:"; 
                }
                else
                {
                    ip4hdr_o.p = IPPROTO_TCP;
                    opts = "a:b:c:d:D:e:E:fF:hH:i:n:p:q:Rs:S:T:o:u:vw:W:Z:";
                }

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
                thdr_o.ackn = (u_int32_t)strtoll(optarg, (char **)NULL, 10);
                break;

            case 'A':
                ahdr_o.op_type = (u_int16_t)atoi(optarg);
                break;

            case 'b':
                burst_rate = (u_int16_t)atoi(optarg);
                break;

            case 'c':
                if(p_mode == M_TRACE && (u_int64_t)atoi(optarg) > 0xFF)
                    fatal_error("Count cannot exceed max TTL value");
                    
                cnt = (u_int64_t)atoi(optarg);
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
                    ehdr_o.rand_s_addr = 1;

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
                    ehdr_o.rand_d_addr = 1;

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
                if(p_mode == M_INJECT)
	            p_mode = M_INJECT_RESPONSE;	

		break;

            case 'H':
                r_timeout = (u_int8_t)atoi(optarg);
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
                    i4hdr_o.orig_s_port = (u_int16_t)atoi(optarg);

                break;

            case 'k':
                i4hdr_o.rtime = (u_int32_t)atoi(optarg);
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
                    i4hdr_o.orig_d_port = (u_int16_t)atoi(optarg);

                break;

            case 'm':
                i4hdr_o.orig_ttl = (u_int16_t)atoi(optarg);
                break;

            case 'M':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    i4hdr_o.rand_orig_id = 1;

                i4hdr_o.orig_id = (u_int16_t)atoi(optarg);
                break;

            case 'n':
                ip4hdr_o.id = (u_int16_t)atoi(optarg);
                ip4hdr_o.rand_id = 0;
                break;

            case 'N':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    i4hdr_o.rand_id = 1;

                i4hdr_o.id = (u_int16_t)atoi(optarg);
                break;

            case 'o':
                ip4hdr_o.tos = (u_int8_t)atoi(optarg);
                break;

            case 'O':
                i4hdr_o.orig_tos = (u_int8_t)atoi(optarg);
                break;

            case 'p':
                if(!strncasecmp(optarg, "0x", 2))
                    hex_payload = 1; 

                if(!(payload = strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'P':
                if(!strcasecmp(optarg, "UDP"))
                    i4hdr_o.orig_p = 17;
                else 
                if(!strncasecmp(optarg, "TCP", 3))
                    i4hdr_o.orig_p = 6;
                else 
                if(!strncasecmp(optarg, "ICMP", 4))
                    i4hdr_o.orig_p = 1;
                else
                    fatal_error("Unknown ICMP original protocol: %s", optarg);

                break;

            case 'q':
                thdr_o.seqn = (u_int32_t)strtoll(optarg, (char **)NULL, 10);
                thdr_o.rand_seqn = 0;
                break;

            case 'Q':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    i4hdr_o.rand_seqn = 1;

                i4hdr_o.seqn = (u_int16_t)strtoll(optarg, (char **)NULL, 10);
                break;

            case 'R':
                resolve = 0;
                break;

            case 's':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    ip4hdr_o.rand_s_addr = 1;

                if(!(ip4hdr_o.s_addr = strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);
		
                break;

            case 'S':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    rand_d_port = 1;
                else
                    rand_s_port = 0;

                s_port = (u_int16_t)atoi(optarg);
                break;

            case 'T':
                if(atoi(optarg) > 0xFF)
                    fatal_error("Invalid TTL value: %s", optarg);

                ip4hdr_o.ttl = (u_int16_t)atoi(optarg);

                break;

            case 'u':
                thdr_o.urp = (u_int16_t)atoi(optarg);
                break;

            case 'U':
                i4hdr_o.otime = (u_int32_t)atoi(optarg);
                break;
 
            case 'v':
                verbose = 1;
                break;

            case 'V':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    ip4hdr_o.rand_p = 1;

                ip4hdr_o.p = (u_int16_t)atoi(optarg);
                break;

            case 'w':
                interval_sec = (u_int16_t)atoi(optarg);
                break;

            case 'W':
                thdr_o.win = (u_int16_t)atoi(optarg);
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

                break;

            case 'y':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    ahdr_o.rand_r_paddr = 1;

                if(!(ahdr_o.r_paddr = strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'Y':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    ahdr_o.rand_r_eaddr = 1;

                if(!(ahdr_o.r_eaddr = strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'z':
                i4hdr_o.ttime = (u_int32_t)atoi(optarg);
                break;

            case 'Z':
                pkt_len = (u_int16_t)atoi(optarg);
                break;
        }
    }

    injection_init();

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
        switch(opt)
        {
            case 'm':
#ifdef WITH_CAPTURE
                if(!strncasecmp(optarg, "CAPTURE", 7) || !strncasecmp(optarg, "C", 1))
                    parse_capture_options(argc, argv);
#endif
#ifdef WITH_INJECTION
                if(!strncasecmp(optarg, "INJECT", 6) || !strncasecmp(optarg, "I", 1))
                    parse_inject_options(argc, argv, M_INJECT);

                if(!strncasecmp(optarg, "TRACE", 10) || !strncasecmp(optarg, "T", 1))
                    parse_inject_options(argc, argv, M_TRACE);
#endif
		
                fprintf(stderr, "\nError: Invalid runtime mode\n");
                print_usage();
 
                break;
            default: 
                optind--;
#ifdef WITH_INJECTION
		parse_inject_options(argc, argv, M_INJECT);
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

    print_usage();

    /* Never gets here */
    exit(SUCCESS);
}        
