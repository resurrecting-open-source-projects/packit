/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2005      Dennis Vshivkov <walrus@amur.ru>
 * Copyright 2006      Deniz Adrian <adrian@netzquadrat.de>
 * Copyright 2013      Mats Erik Andersson <gnu@gisladisker.se>
 * Copyright 2017      Robert Krause <ruport@f00l.de>
 * Copyright 2017      Sharad B
 * Copyright 2020      Jeroen Roovers <jer@gentoo.org>
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

#include "main.h"

char g_w_file[OPT_MAXLEN];
char g_r_file[OPT_MAXLEN];

pcap_t *g_pkt;
u_int8_t g_tr_fin;
char *g_filter;
char *g_device;
u_int16_t g_hdr_len;
u_int16_t g_pkt_len;
u_int16_t g_verbose;
u_int16_t g_resolve;
u_int16_t g_p_mode;
u_int64_t g_cnt;
u_int64_t g_inj_cnt;
u_int64_t g_cap_cnt;

/* capture_defs.h */
u_int16_t g_display;
u_int16_t g_link_layer;
u_int16_t g_dump_pkt;
u_int16_t g_time_gmt;
u_int16_t g_t_rst;
u_int16_t g_snap_len;
u_int32_t g_pkt_rst;

/* inject_defs.h */
u_int16_t g_init_type;
u_int16_t g_rand_d_port;
u_int16_t g_rand_s_port;
u_int16_t g_s_port;
u_int16_t g_d_port;
u_int16_t g_port_range;
u_int16_t g_interval_sec;
u_int16_t g_interval_usec;
u_int16_t g_injection_type;
u_int16_t g_r_timeout;
u_int16_t g_burst_rate;
u_int16_t g_payload_len;
u_int8_t *g_payload;
u_int8_t g_hex_payload;
u_int8_t *g_s_d_port;
u_int8_t g_hwaddr_p[18];
u_int8_t g_rawip;

struct timeval g_bf_pcap;
struct timeval g_af_pcap;

struct arphdr_opts g_ahdr_o;
struct enethdr_opts g_ehdr_o;
struct icmp4hdr_opts g_i4hdr_o;
struct ip4hdr_opts g_ip4hdr_o;
struct tcphdr_opts g_thdr_o;
struct udphdr_opts g_uhdr_o;

libnet_t *g_pkt_d;

void
parse_capture_options(int argc, char *argv[])
{
    g_p_mode = M_CAPTURE;
    g_cnt = 0;
    g_cap_cnt = 0;
    g_snap_len = SNAPLEN_DEFAULT;
    g_resolve = 3;
    g_verbose = 0;
    g_display = 1;
    g_link_layer = 0;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: parse_capture_options()\n");
#endif

    while((opt = getopt(argc, argv, "c:eGi:nNr:Rs:vw:xX")) != -1)
    {
        switch(opt)
        {
            case 'c':
                g_cnt = (u_int64_t)atoi(optarg);
                break;

            case 'e':
                g_link_layer = 1;
                break;

	    case 'G':
		g_time_gmt = 1;
		break;

            case 'i':
                if(!(g_device = strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);
                break;

            case 'w':
                strncpy(g_w_file, optarg, OPT_MAXLEN);
                break;

            case 'r':
                strncpy(g_r_file, optarg, OPT_MAXLEN);
                break;

            case 's':
		g_snap_len = (u_int16_t)atoi(optarg);
		break;

            case 'v':
               g_verbose = 1;
               break;

            case 'n':
                g_resolve--;
	        break;

	    case 'x': case 'X':
		g_dump_pkt = 1;
		break;
        }
    }

    capture_init(argv[optind], g_cnt);

    return;
}

void
parse_inject_options(int argc, char *argv[], u_int16_t iopt)
{
    char *opts = NULL;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: parse_inject_options(%d)\n", g_p_mode);
#endif

    if(getuid() != 0) fatal_error("Sorry, you're not root!");

    g_p_mode = iopt;

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
                    g_ip4hdr_o.p = IPPROTO_TCP;
                    g_injection_type = ETHERTYPE_IP;
                    opts = "a:b:c:d:D:e:E:fF:hH:i:n:p:q:Rs:S:T:o:u:vw:W:Z:";
                }
                else
                if(!strncasecmp(optarg, "UDP", 3))
                {
#ifdef DEBUG
                    fprintf(stdout, "DEBUG: UDP injection\n");
#endif
                    g_ip4hdr_o.p = IPPROTO_UDP;
                    g_injection_type = ETHERTYPE_IP;
                    opts = "b:c:d:D:e:E:fhH:i:n:o:p:Rs:S:T:vw:Z:";
                }
                else
                if(!strncasecmp(optarg, "ICMP", 4))
                {
#ifdef DEBUG
                    fprintf(stdout, "DEBUG: ICMP injection\n");
#endif
                    g_ip4hdr_o.p = IPPROTO_ICMP;
                    g_injection_type = ETHERTYPE_IP;
                    opts = "b:c:C:d:e:E:fg:G:hH:i:j:J:k:K:l:L:m:M:n:N:o:O:p:P:Q:Rs:t:T:U:vw:z:Z:";
                }
		else
                if(!strncasecmp(optarg, "ARP", 3))
                {
                    if(g_p_mode == M_TRACE)
                        fatal_error("ARP is not supported with trace mode.");
#ifdef DEBUG
                    fprintf(stdout, "DEBUG: ARP injection\n");
#endif
#ifdef MACOS
                    fprintf(stderr, "\nError: ARP injection is not yet supported on this OS platform.\n");
                    exit(FAILURE);
#endif
                    g_injection_type = ETHERTYPE_ARP;
                    g_init_type = 0;
                    opts = "A:b:c:e:E:i:p:Rs:S:vx:X:y:Y:";
                }
                else
                if(!strncasecmp(optarg, "RARP", 4))
                {
                    if(g_p_mode == M_TRACE)
                        fatal_error("RARP is not supported with trace mode.");
#ifdef DEBUG
                    fprintf(stdout, "DEBUG: RARP injection\n");
#endif
#ifdef MACOS
                    fprintf(stderr, "\nError: RARP injection is not yet supported on this OS platform.\n");
                    exit(FAILURE);
#endif
                    g_injection_type = ETHERTYPE_REVARP;
                    g_ahdr_o.op_type = ARPOP_REVREQUEST; /* Update init */
                    g_init_type = 0;
                    opts = "A:b:c:e:E:i:p:Rs:S:vx:X:y:Y:";
                }
                else
                if(!strncasecmp(optarg, "RAWIP", 3))
                {
                    if(g_p_mode == M_TRACE)
                        fatal_error("RAW is not supported with trace mode.");
#ifdef DEBUG
                    fprintf(stdout, "DEBUG: raw IP injection\n");
#endif
                    g_rawip = g_ip4hdr_o.p = IPPROTO_RAW;
                    g_injection_type = ETHERTYPE_IP;
                    opts = "b:c:d:e:E:f:i:n:o:p:Rs:T:U:vV:w:Z:";
                }
                else
                    print_usage();

                goto parse_inject;

                break;

            default:
                if(optind > 1) optind--;
                g_injection_type = ETHERTYPE_IP;

                if(g_p_mode == M_TRACE)
                {
                    g_ip4hdr_o.p = IPPROTO_ICMP;
                    opts = "b:c:C:d:e:E:fg:G:hH:i:j:J:k:K:l:L:m:M:n:N:o:O:p:P:Q:Rs:t:T:U:vw:z:Z:";
                }
                else
                {
                    g_ip4hdr_o.p = IPPROTO_TCP;
                    opts = "a:b:c:d:D:e:E:fF:hH:i:n:p:q:Rs:S:T:o:u:vw:W:Z:";
                }

                goto parse_inject;

                break;
        }
    }

print_usage();

parse_inject:
#ifdef DEBUG
    fprintf(stdout, "DEBUG: parse_inject\n");
#endif

    while((opt = getopt(argc, argv, opts)) != -1)
    {
        switch(opt)
        {
            case 'a':
                g_thdr_o.ackn = (u_int32_t)strtoll(optarg, (char **)NULL, 10);
                break;

            case 'A':
                g_ahdr_o.op_type = (u_int16_t)atoi(optarg);
                break;

            case 'b':
                g_burst_rate = (u_int16_t)atoi(optarg);
                break;

            case 'c':
                if(g_p_mode == M_TRACE && (u_int64_t)atoi(optarg) > 0xFF)
                    fatal_error("Count cannot exceed max TTL value");

                g_cnt = (u_int64_t)atoi(optarg);
                break;

            case 'C':
                g_i4hdr_o.code = (u_int16_t)atoi(optarg);
                break;

            case 'd':
	        if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_ip4hdr_o.rand_d_addr = 1;

		if(!(g_ip4hdr_o.d_addr = (u_int8_t*)strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'D':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_rand_d_port = 1;

                if(!(g_s_d_port = (u_int8_t*)strdup(optarg)) && !g_rand_d_port)
		    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'e':
#ifdef MACOS
            fprintf(stderr, "\nWarning: You cannot specify an ethernet address on this operating system.\n");
	    break;
#endif
		if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_ehdr_o.rand_s_addr = 1;

      		if(!(g_ehdr_o.s_addr = (u_int8_t*)strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);

                g_init_type = 0;
                g_link_layer = 1;
                break;

            case 'E':
#ifdef MACOS
                fprintf(stderr, "\nWarning: You cannot specify an ethernet address on this operating system.\n");
		break;
#endif
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_ehdr_o.rand_d_addr = 1;

                if(!(g_ehdr_o.d_addr = (u_int8_t*)strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);

                g_init_type = 0;
                g_link_layer = 1;
                break;

	    case 'f':
		g_ip4hdr_o.frag = 0x4000;
		break;

            case 'F':
                if(strrchr(optarg, 'U'))
                    g_thdr_o.urg = 1;

                if(strrchr(optarg, 'A'))
                    g_thdr_o.ack = 1;

                if(strrchr(optarg, 'P'))
                    g_thdr_o.psh = 1;

                if(strrchr(optarg, 'R'))
                    g_thdr_o.rst = 1;

                if(strrchr(optarg, 'S'))
                    g_thdr_o.syn = 1;

                if(strrchr(optarg, 'F'))
                    g_thdr_o.fin = 1;

                break;

            case 'g':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_i4hdr_o.rand_gw = 1;

                if(!(g_i4hdr_o.gw = (u_int8_t*)strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'G':
                if(!(g_i4hdr_o.mask = (u_int8_t*)strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

	    case 'h':
                if(g_p_mode == M_INJECT)
	            g_p_mode = M_INJECT_RESPONSE;	

		break;

            case 'H':
                g_r_timeout = (u_int8_t)atoi(optarg);
                break;

            case 'i':
                if(!(g_device = strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'j':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_i4hdr_o.rand_orig_s_addr = 1;

                if(!(g_i4hdr_o.orig_s_addr = (u_int8_t*)strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'J':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_i4hdr_o.rand_orig_s_port = 1;
                else
                    g_i4hdr_o.orig_s_port = (u_int16_t)atoi(optarg);

                break;

            case 'k':
                g_i4hdr_o.rtime = (u_int32_t)atoi(optarg);
                break;

            case 'K':
                g_i4hdr_o.type = (u_int16_t)atoi(optarg);
                break;

            case 'l':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_i4hdr_o.rand_orig_d_addr = 1;

                if(!(g_i4hdr_o.orig_d_addr = (u_int8_t*)strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'L':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_i4hdr_o.rand_orig_d_port = 1;
                else
                    g_i4hdr_o.orig_d_port = (u_int16_t)atoi(optarg);

                break;

            case 'm':
                g_i4hdr_o.orig_ttl = (u_int16_t)atoi(optarg);
                break;

            case 'M':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_i4hdr_o.rand_orig_id = 1;

                g_i4hdr_o.orig_id = (u_int16_t)atoi(optarg);
                break;

            case 'n':
                g_ip4hdr_o.id = (u_int16_t)atoi(optarg);
                g_ip4hdr_o.rand_id = 0;
                break;

            case 'N':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_i4hdr_o.rand_id = 1;

                g_i4hdr_o.id = (u_int16_t)atoi(optarg);
                break;

            case 'o':
                g_ip4hdr_o.tos = (u_int8_t)atoi(optarg);
                break;

            case 'O':
                g_i4hdr_o.orig_tos = (u_int8_t)atoi(optarg);
                break;

            case 'p':
                if(!strncasecmp(optarg, "0x", 2))
                    g_hex_payload = 1;

                if(!(g_payload = (u_int8_t*)strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'P':
                if(!strcasecmp(optarg, "UDP"))
                    g_i4hdr_o.orig_p = 17;
                else
                if(!strncasecmp(optarg, "TCP", 3))
                    g_i4hdr_o.orig_p = 6;
                else
                if(!strncasecmp(optarg, "ICMP", 4))
                    g_i4hdr_o.orig_p = 1;
                else
                    fatal_error("Unknown ICMP original protocol: %s", optarg);

                break;

            case 'q':
                g_thdr_o.seqn = (u_int32_t)strtoll(optarg, (char **)NULL, 10);
                g_thdr_o.rand_seqn = 0;
                break;

            case 'Q':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_i4hdr_o.rand_seqn = 1;

                g_i4hdr_o.seqn = (u_int16_t)strtoll(optarg, (char **)NULL, 10);
                break;

            case 'R':
                g_resolve = 0;
                break;

            case 's':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_ip4hdr_o.rand_s_addr = 1;

                if(!(g_ip4hdr_o.s_addr = (u_int8_t*)strdup(optarg)))
		    fatal_error("Memory unavailable for: %s", optarg);
                break;

            case 'S':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_rand_s_port = 1;
                else
                    g_rand_s_port = 0;

                g_s_port = (u_int16_t)atoi(optarg);
                break;

            case 'T':
                if(atoi(optarg) > 0xFF)
                    fatal_error("Invalid TTL value: %s", optarg);

                g_ip4hdr_o.ttl = (u_int16_t)atoi(optarg);

                break;

            case 'u':
                g_thdr_o.urp = (u_int16_t)atoi(optarg);
                break;

            case 'U':
                g_i4hdr_o.otime = (u_int32_t)atoi(optarg);
                break;

            case 'v':
                g_verbose = 1;
                break;

            case 'V':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_ip4hdr_o.rand_p = 1;

                g_ip4hdr_o.p = (u_int16_t)atoi(optarg);
                break;

            case 'w':
                g_interval_sec = (u_int16_t)atoi(optarg);
                break;

            case 'W':
                g_thdr_o.win = (u_int16_t)atoi(optarg);
                break;

            case 'x':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_ahdr_o.rand_s_paddr = 1;

                if(!(g_ahdr_o.s_paddr = (u_int8_t*)strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'X':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_ahdr_o.rand_s_eaddr = 1;

                if(!(g_ahdr_o.s_eaddr = (u_int8_t*)strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'y':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_ahdr_o.rand_r_paddr = 1;

                if(!(g_ahdr_o.r_paddr = (u_int8_t*)strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'Y':
                if(strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
                    g_ahdr_o.rand_r_eaddr = 1;

                if(!(g_ahdr_o.r_eaddr = (u_int8_t*)strdup(optarg)))
                    fatal_error("Memory unavailable for: %s", optarg);

                break;

            case 'z':
                g_i4hdr_o.ttime = (u_int32_t)atoi(optarg);
                break;

            case 'Z':
                g_pkt_len = (u_int16_t)atoi(optarg);
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
