/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2004-2005 Dennis Vshivkov <walrus@amur.ru>
 * Copyright 2006      Deniz Adrian <adrian@netzquadrat.de>
 * Copyright 2013      Mats Erik Andersson <gnu@gisladisker.se>
 * Copyright 2017      Robert Krause <ruport@f00l.de>
 * Copyright 2017      Sharad B
 * Copyright 2020      David Polverari <david.polverari@gmail.com>
 * Copyright 2020      Jeroen Roovers <jer@gentoo.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#include "main.h"
#include "options.h"

static void parse_inject(int argc, char *argv[], char *opts);
static void randomisable_str(u_int8_t ** to, u_int16_t * rand, size_t size,
			     const char *desc);

u_int16_t parse_mode(int argc, char *argv[])
{
	u_int16_t mode;

	opterr = 0;
	mode = M_INJECT;	/* default mode */
#ifdef DEBUG
	fprintf(stdout, "DEBUG: parse_mode()\n");
#endif
	if ((opt = getopt(argc, argv, ":m:")) != -1) {
		switch (opt) {
		case 'm':
			if (!strncasecmp(optarg, "capture", 7))
				mode = M_CAPTURE;
			else if (!strncasecmp(optarg, "inject", 6))
				mode = M_INJECT;
			else if (!strncasecmp(optarg, "trace", 10))
				mode = M_TRACE;
			else
				fatal_error("invalid mode.\n");
			break;
		case ':':
			fprintf(stderr, "\nError: no mode specified\n");
			exit(EXIT_FAILURE);
			break;
		case '?':
			optind--;
			break;
		}
	}
	return mode;
}

void parse_capture_options(int argc, char *argv[])
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
#ifndef WITH_CAPTURE
	fatal_error("Packit wasn't built with capture support!");
#endif
	while ((opt = getopt(argc, argv, ":c:eGi:nNr:Rs:vw:xX")) != -1) {
		switch (opt) {
		case 'c':
			g_cnt = (u_int64_t) atoi(optarg);
			break;
		case 'e':
			g_link_layer = 1;
			break;
		case 'G':
			g_time_gmt = 1;
			break;
		case 'i':
			if (!(g_device = strdup(optarg)))
				fatal_error("Memory unavailable for: %s",
					    optarg);
			break;
		case 'w':
			strncpy(g_w_file, optarg, OPT_MAXLEN);
			break;
		case 'r':
			strncpy(g_r_file, optarg, OPT_MAXLEN);
			break;
		case 's':
			g_snap_len = (u_int16_t) atoi(optarg);
			break;
		case 'v':
			g_verbose = 1;
			break;
		case 'n':
			g_resolve--;
			break;
		case 'x':
		case 'X':
			g_dump_pkt = 1;
			break;
		case '?':
			fprintf(stderr,
				"\nError: illegal capture option: -%c.\n",
				optopt);
			exit(EXIT_FAILURE);
			break;
		case ':':
			fprintf(stderr,
				"\nError: Missing argument for capture option -%c.\n",
				optopt);
			exit(EXIT_FAILURE);
			break;
		}
	}
	capture_init(argv[optind], g_cnt);
}

void parse_inject_options(int argc, char *argv[], u_int16_t iopt)
{
	char *opts = NULL;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: parse_inject_options(%d)\n", g_p_mode);
#endif
#ifndef WITH_INJECTION
	fatal_error("Packit was not built with injection support!");
#endif
	if (getuid() != 0)
		fatal_error("Sorry, you're not root!");
	g_p_mode = iopt;
	define_injection_defaults();
	injection_struct_init();
	while ((opt = getopt(argc, argv, ":t:")) != -1) {
		switch (opt) {
		case 't':
			if (!strncasecmp(optarg, "TCP", 3)) {
#ifdef DEBUG
				fprintf(stdout, "DEBUG: TCP injection\n");
#endif
				g_ip4hdr_o.p = IPPROTO_TCP;
				g_injection_type = ETHERTYPE_IP;
				opts =
				    ":a:b:c:d:D:e:E:fF:hH:i:I:n:p:q:Rs:S:T:o:u:vw:W:Z:";
			} else if (!strncasecmp(optarg, "UDP", 3)) {
#ifdef DEBUG
				fprintf(stdout, "DEBUG: UDP injection\n");
#endif
				g_ip4hdr_o.p = IPPROTO_UDP;
				g_injection_type = ETHERTYPE_IP;
				opts =
				    ":b:c:d:D:e:E:fhH:i:I:n:o:p:Rs:S:T:vw:Z:";
			} else if (!strncasecmp(optarg, "ICMP", 4)) {
#ifdef DEBUG
				fprintf(stdout, "DEBUG: ICMP injection\n");
#endif
				g_ip4hdr_o.p = IPPROTO_ICMP;
				g_injection_type = ETHERTYPE_IP;
				opts =
				    ":b:c:C:d:e:E:fg:G:hH:i:I:j:J:k:K:l:L:m:M:n:N:o:O:p:P:Q:Rs:t:T:U:vw:z:Z:";
			} else if (!strncasecmp(optarg, "ARP", 3)) {
				if (g_p_mode == M_TRACE)
					fatal_error
					    ("ARP is not supported with trace mode.");
#ifdef DEBUG
				fprintf(stdout, "DEBUG: ARP injection\n");
#endif
#ifdef MACOS
				fprintf(stderr,
					"\nError: ARP injection is not yet supported on this OS platform.\n");
				exit(EXIT_FAILURE);
#endif
				g_injection_type = ETHERTYPE_ARP;
				g_init_type = 0;
				opts = ":A:b:c:e:E:i:I:p:Rs:S:vx:X:y:Y:";
			} else if (!strncasecmp(optarg, "RARP", 4)) {
				if (g_p_mode == M_TRACE)
					fatal_error
					    ("RARP is not supported with trace mode.");
#ifdef DEBUG
				fprintf(stdout, "DEBUG: RARP injection\n");
#endif
#ifdef MACOS
				fprintf(stderr,
					"\nError: RARP injection is not yet supported on this OS platform.\n");
				exit(EXIT_FAILURE);
#endif
				g_injection_type = ETHERTYPE_REVARP;
				g_ahdr_o.op_type = ARPOP_REVREQUEST;	/* Update init */
				g_init_type = 0;
				opts = ":A:b:c:e:E:i:p:Rs:S:vx:X:y:Y:";
			} else if (!strncasecmp(optarg, "RAWIP", 3)) {
				if (g_p_mode == M_TRACE)
					fatal_error
					    ("RAW is not supported with trace mode.");
#ifdef DEBUG
				fprintf(stdout, "DEBUG: raw IP injection\n");
#endif
				g_rawip = g_ip4hdr_o.p = IPPROTO_RAW;
				g_injection_type = ETHERTYPE_IP;
				opts = ":b:c:d:e:E:f:i:n:o:p:Rs:T:U:vV:w:Z:";
			} else {
				print_usage();
				exit(EXIT_FAILURE);
			}
			parse_inject(argc, argv, opts);
			break;
		case ':':
			fprintf(stderr,
				"\nError: Missing argument for option -%c.\n",
				optopt);
			exit(EXIT_FAILURE);
			break;
		case '?':
			if (optind > 1)
				optind--;
			g_injection_type = ETHERTYPE_IP;
			if (g_p_mode == M_TRACE) {
				g_ip4hdr_o.p = IPPROTO_ICMP;
				opts =
				    ":b:c:C:d:e:E:fg:G:hH:i:j:J:k:K:l:L:m:M:n:N:o:O:p:P:Q:Rs:t:T:U:vw:z:Z:";
			} else {
				g_ip4hdr_o.p = IPPROTO_TCP;
				opts =
				    ":a:b:c:d:D:e:E:fF:hH:i:I:n:p:q:Rs:S:T:o:u:vw:W:Z:";
			}
			parse_inject(argc, argv, opts);
			break;
		}
	}
}

static void parse_inject(int argc, char *argv[], char *opts)
{
	u_int16_t protocol;
	struct name_proto {
		char *name;
		u_int16_t id;
	} ip_protocols[] = {
		{"TCP", IPPROTO_TCP},
		{"UDP", IPPROTO_UDP},
		{"ICMP", IPPROTO_ICMP},
		{"raw IP", IPPROTO_RAW},
		{NULL, 0}
	}, ll_protocols[] = {
		{"ARP", ETHERTYPE_ARP},
		{"RARP", ETHERTYPE_REVARP},
		{NULL, 0}
	}, *row;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: parse_inject()\n");
#endif
	while ((opt = getopt(argc, argv, opts)) != -1) {
		switch (opt) {
		case 'a':
			g_thdr_o.ackn =
			    (u_int32_t) strtoll(optarg, (char **)NULL, 10);
			break;
		case 'A':
			g_ahdr_o.op_type = (u_int16_t) atoi(optarg);
			break;
		case 'b':
			g_burst_rate = (u_int16_t) atoi(optarg);
			break;
		case 'c':
			if (g_p_mode == M_TRACE
			    && (u_int64_t) atoi(optarg) > 0xFF)
				fatal_error
				    ("Count cannot exceed max TTL value");
			g_cnt = (u_int64_t) atoi(optarg);
			break;
		case 'C':
			g_i4hdr_o.code = (u_int16_t) atoi(optarg);
			break;
		case 'd':
			randomisable_str(&g_ip4hdr_o.d_addr,
					 &g_ip4hdr_o.rand_d_addr, 16,
					 "destination IP");
			break;
		case 'D':
			if (strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
				g_rand_d_port = 1;
			if (!(g_s_d_port = (u_int8_t *) strdup(optarg))
			    && !g_rand_d_port)
				fatal_error("Memory unavailable for: %s",
					    optarg);
			break;
		case 'e':
#ifdef MACOS
			fprintf(stderr,
				"\nWarning: You cannot specify an ethernet address on this operating system.\n");
			break;
#endif
			randomisable_str(&g_ehdr_o.s_addr,
					 &g_ehdr_o.rand_s_addr, 18,
					 "source MAC");
			g_init_type = 0;
			g_link_layer = 1;
			break;
		case 'E':
#ifdef MACOS
			fprintf(stderr,
				"\nWarning: You cannot specify an ethernet address on this operating system.\n");
			break;
#endif
			randomisable_str(&g_ehdr_o.d_addr,
					 &g_ehdr_o.rand_d_addr, 18,
					 "destination MAC");
			g_init_type = 0;
			g_link_layer = 1;
			break;
		case 'f':
			g_ip4hdr_o.frag = 0x4000;
			break;
		case 'F':
			if (strrchr(optarg, 'U'))
				g_thdr_o.urg = 1;
			if (strrchr(optarg, 'A'))
				g_thdr_o.ack = 1;
			if (strrchr(optarg, 'P'))
				g_thdr_o.psh = 1;
			if (strrchr(optarg, 'R'))
				g_thdr_o.rst = 1;
			if (strrchr(optarg, 'S'))
				g_thdr_o.syn = 1;
			if (strrchr(optarg, 'F'))
				g_thdr_o.fin = 1;
			break;
		case 'g':
			randomisable_str(&g_i4hdr_o.gw, &g_i4hdr_o.rand_gw, 16,
					 "gateway IP");
			break;
		case 'G':
			if (!(g_i4hdr_o.mask = (u_int8_t *) strdup(optarg)))
				fatal_error("Memory unavailable for: %s",
					    optarg);
			break;
		case 'h':
			if (g_p_mode == M_INJECT)
				g_p_mode = M_INJECT_RESPONSE;
			break;
		case 'H':
			g_r_timeout = (u_int8_t) atoi(optarg);
			break;
		case 'i':
			if (!(g_device = strdup(optarg)))
				fatal_error("Memory unavailable for: %s",
					    optarg);
			break;
		case 'I':
			g_ehdr_o.dot1q_vlan_id_cpi_prio =
			    (u_int16_t) atoi(optarg);
			g_init_type = LIBNET_LINK;
			break;
		case 'j':
			randomisable_str(&g_i4hdr_o.orig_s_addr,
					 &g_i4hdr_o.rand_orig_s_addr, 16,
					 "original source IP");
			break;
		case 'J':
			if (strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
				g_i4hdr_o.rand_orig_s_port = 1;
			else
				g_i4hdr_o.orig_s_port =
				    (u_int16_t) atoi(optarg);
			break;
		case 'k':
			g_i4hdr_o.rtime = (u_int32_t) atoi(optarg);
			break;
		case 'K':
			g_i4hdr_o.type = (u_int16_t) atoi(optarg);
			break;
		case 'l':
			randomisable_str(&g_i4hdr_o.orig_d_addr,
					 &g_i4hdr_o.rand_orig_d_addr, 16,
					 "original destination IP");
			break;
		case 'L':
			if (strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
				g_i4hdr_o.rand_orig_d_port = 1;
			else
				g_i4hdr_o.orig_d_port =
				    (u_int16_t) atoi(optarg);
			break;
		case 'm':
			g_i4hdr_o.orig_ttl = (u_int16_t) atoi(optarg);
			break;
		case 'M':
			if (strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
				g_i4hdr_o.rand_orig_id = 1;
			g_i4hdr_o.orig_id = (u_int16_t) atoi(optarg);
			break;
		case 'n':
			g_ip4hdr_o.id = (u_int16_t) atoi(optarg);
			g_ip4hdr_o.rand_id = 0;
			break;
		case 'N':
			if (strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
				g_i4hdr_o.rand_id = 1;
			g_i4hdr_o.id = (u_int16_t) atoi(optarg);
			break;
		case 'o':
			g_ip4hdr_o.tos = (u_int8_t) atoi(optarg);
			break;
		case 'O':
			g_i4hdr_o.orig_tos = (u_int8_t) atoi(optarg);
			break;
		case 'p':
			if (!strncasecmp(optarg, "0x", 2))
				g_hex_payload = 1;
			if (!(g_payload = (u_int8_t *) strdup(optarg)))
				fatal_error("Memory unavailable for: %s",
					    optarg);
			break;
		case 'P':
			if (!strcasecmp(optarg, "UDP"))
				g_i4hdr_o.orig_p = 17;
			else if (!strncasecmp(optarg, "TCP", 3))
				g_i4hdr_o.orig_p = 6;
			else if (!strncasecmp(optarg, "ICMP", 4))
				g_i4hdr_o.orig_p = 1;
			else
				fatal_error
				    ("Unknown ICMP original protocol: %s",
				     optarg);
			break;
		case 'q':
			g_thdr_o.seqn =
			    (u_int32_t) strtoll(optarg, (char **)NULL, 10);
			g_thdr_o.rand_seqn = 0;
			break;
		case 'Q':
			if (strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
				g_i4hdr_o.rand_seqn = 1;
			g_i4hdr_o.seqn =
			    (u_int16_t) strtoll(optarg, (char **)NULL, 10);
			break;
		case 'R':
			g_resolve = 0;
			break;
		case 's':
			randomisable_str(&g_ip4hdr_o.s_addr,
					 &g_ip4hdr_o.rand_s_addr, 16,
					 "source IP");
			break;
		case 'S':
			if (strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
				g_rand_s_port = 1;
			else
				g_rand_s_port = 0;
			g_s_port = (u_int16_t) atoi(optarg);
			break;
		case 'T':
			if (atoi(optarg) > 0xFF)
				fatal_error("Invalid TTL value: %s", optarg);
			g_ip4hdr_o.ttl = (u_int16_t) atoi(optarg);
			break;
		case 'u':
			g_thdr_o.urp = (u_int16_t) atoi(optarg);
			break;
		case 'U':
			g_i4hdr_o.otime = (u_int32_t) atoi(optarg);
			break;
		case 'v':
			g_verbose = 1;
			break;
		case 'V':
			if (strlen(optarg) == 1 && !strncmp(optarg, "R", 1))
				g_ip4hdr_o.rand_p = 1;
			g_ip4hdr_o.p = (u_int16_t) atoi(optarg);
			break;
		case 'w':
			g_interval_sec = (u_int16_t) atoi(optarg);
			break;
		case 'W':
			g_thdr_o.win = (u_int16_t) atoi(optarg);
			break;
		case 'x':
			randomisable_str(&g_ahdr_o.s_paddr,
					 &g_ahdr_o.rand_s_paddr, 16,
					 "ARP sender IP");
			break;
		case 'X':
			randomisable_str(&g_ahdr_o.s_eaddr,
					 &g_ahdr_o.rand_s_eaddr, 18,
					 "ARP sender MAC");
			break;
		case 'y':
			randomisable_str(&g_ahdr_o.r_paddr,
					 &g_ahdr_o.rand_r_paddr, 16,
					 "ARP receiver IP");
			break;
		case 'Y':
			randomisable_str(&g_ahdr_o.r_eaddr,
					 &g_ahdr_o.rand_r_eaddr, 18,
					 "ARP receiver MAC");
			break;
		case 'z':
			g_i4hdr_o.ttime = (u_int32_t) atoi(optarg);
			break;
		case 'Z':
			g_pkt_len = (u_int16_t) atoi(optarg);
			break;
		case '?':
			if (g_injection_type == ETHERTYPE_IP) {
				protocol = g_ip4hdr_o.p;
				row = ip_protocols;
			} else {
				protocol = g_injection_type;
				row = ll_protocols;
			}
			while (row->name && (row->id != protocol))
				row++;
			fprintf(stderr,
				"\nError: illegal option -%c in %s %s.\n",
				optopt, row->name, (g_p_mode == M_INJECT
						    || g_p_mode ==
						    M_INJECT_RESPONSE) ?
				"injection" : "tracing");
			break;
		case ':':
			fprintf(stderr,
				"\nError: missing argument for option -%c.\n",
				optopt);
			exit(EXIT_FAILURE);
			break;
		}
	}
	injection_init();
}

static void
randomisable_str(u_int8_t ** to, u_int16_t * rand, size_t size,
		 const char *desc)
{
	if (strcmp(optarg, "R") != 0) {
		if ((*to = (unsigned char *)strdup(optarg)) == NULL)
			fatal_error("Memory unavailable for: %s", optarg);
	} else {
		*rand = 1;
		if ((*to = malloc(size)) == NULL)
			fatal_error("Memory unavailable for: %s", desc);
	}
}
