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

#include <stdio.h>
#include <stdlib.h>

#include "globals.h"
#include "options.h"
#include "inject_defs.h"
#include "usage.h"

#define OPT_MAXLEN 32

char g_w_file[OPT_MAXLEN + 1];
char g_r_file[OPT_MAXLEN + 1];

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

int main(int argc, char *argv[])
{
	u_int16_t mode;

	if (argc < 2) {
		print_usage();
		exit(EXIT_SUCCESS);
	}
#ifdef DEBUG
	fprintf(stdout, "DEBUG: main()\n");
#endif
	if ((mode = parse_mode(argc, argv)) == -1) {
		fprintf(stderr, "\nError: Invalid runtime mode\n");
		print_usage();
		exit(EXIT_FAILURE);
	}
	if (mode == M_CAPTURE) {
		parse_capture_options(argc, argv);
	} else {
		parse_inject_options(argc, argv, mode);
	}
	return EXIT_SUCCESS;
}
