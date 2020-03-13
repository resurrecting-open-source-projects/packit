/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2017 Robert Krause <ruport@f00l.de>
 * Copyright 2017 Sharad B
 * Copyright 2019 Sander Kleijwegt <sander.kleijwegt@netscout.com>
 * Copyright 2020 David Polverari <david.polverari@gmail.com>
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

#include "injection.h"

u_int16_t inject_packet()
{
#ifdef DEBUG
	fprintf(stdout, "DEBUG: inject_packet()\n");
#endif
	if (libnet_write(g_pkt_d) == -1)
		return FAILURE;
	return SUCCESS;
}

void injection_init()
{
	u_int16_t g_port_range = 0;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: injection_init()\n");
	fprintf(stdout, "DEBUG: g_cnt: %ld, g_interval_sec %d\n", g_cnt,
		g_interval_sec);
	fprintf(stdout, "DEBUG: g_p_mode: %d  g_burst_rate: %d\n", g_p_mode,
		g_burst_rate);
#endif
	signal(SIGTERM, injection_clean_exit);
	signal(SIGQUIT, injection_clean_exit);
	signal(SIGINT, injection_clean_exit);
	signal(SIGHUP, injection_clean_exit);
	if (g_hex_payload) {
		if ((g_payload_len =
		     format_hex_payload((char *)g_payload)) == 0)
			fprintf(stdout,
				"Warning: Hex payload formatted incorrectly.\n");
	} else if (g_payload) {
		g_payload_len = strlen((char *)g_payload);
#ifdef DEBUG
		fprintf(stdout, "DEBUG: g_payload_len=%d\n", g_payload_len);
#endif
	}
	if (g_s_d_port != NULL) {
		if (strstr((char *)g_s_d_port, "-")) {
			g_cnt = parse_port_range((char *)g_s_d_port);
			if (g_cnt < 1 || g_cnt > 65535)
				fatal_error("Invalid port range: %s",
					    g_s_d_port);
			g_port_range = 1;
		}
		g_d_port = (u_int16_t) atoi((char *)g_s_d_port);
	}
	if (!g_device) {
		pcap_if_t *alldevsp = NULL;
		if (pcap_findalldevs(&alldevsp, error_buf) == -1
		    || alldevsp == NULL) {
			fatal_error("Device lookup failure: Are you root?");
		} else {
			g_device = strdup(alldevsp->name);
			pcap_freealldevs(alldevsp);
		}
	}
	if (strstr(g_device, "any"))
		strcpy(g_device, "lo");
	if (g_p_mode == M_TRACE)
		fprintf(stdout,
			"Mode:  Trace Route [Hop Max: %lu] using device: %s\n",
			g_cnt, g_device);
	else
		fprintf(stdout, "Mode:  Packet Injection using device: %s\n",
			g_device);
	if ((g_pkt_d = libnet_init(g_init_type, g_device, error_buf)) == NULL)
		fatal_error("Unable to initialize packet injection");
	if (g_p_mode == M_INJECT)
		without_response(g_port_range);
	else if (g_p_mode == M_INJECT_RESPONSE || g_p_mode == M_TRACE)
		with_response(g_port_range);
#ifdef DEBUG
	fprintf(stdout, "DEBUG: Preparing to clean house and exit\n");
#endif
	injection_clean_exit(SUCCESS);
}

u_int16_t with_response(u_int32_t g_port_range)
{
	char ufilter[1024];
	u_int32_t i, tr_retry = 0;
	u_int32_t dth_r, dstp = 0;
	u_int32_t localnet, netmask;
	u_int32_t d_link;

	struct bpf_program bpf;
	struct timespec n_sleep;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: with_response()\n");
#endif
	memset(&bpf, 0, sizeof(struct bpf_program));
	memset(&n_sleep, 0, sizeof(struct timespec));
	n_sleep.tv_nsec = 100;
	if (g_init_type == 0)
		g_link_layer = 1;
	if ((g_pkt =
	     pcap_open_live(g_device, 1500, 1, READ_TIMEOUT,
			    error_buf)) == NULL)
		fatal_error("Unable to open device: %s", error_buf);
	if (pcap_lookupnet(g_device, &localnet, &netmask, error_buf) < 0)
		fprintf(stderr, "\nWarning: Unable to lookup network: %s\n",
			error_buf);
	if (g_cnt == 0)
		dstp = g_cnt = 1;
	for (i = 1; i < g_cnt + 1; i++) {
#ifdef DEBUG
		fprintf(stdout, "DEBUG: for() g_inj_cnt: %ld  g_cnt: %ld\n",
			g_inj_cnt, g_cnt);
#endif
		if (dstp)
			i = 0;
		g_pkt_d = shape_packet();
		switch (g_ip4hdr_o.p) {
		case IPPROTO_TCP:
			snprintf(ufilter, 1024,
				 "dst host %s"
				 " && "
				 "(ip[9] = 6 && src host %s && src port 0x%x && dst port 0x%x)"
				 " || "
				 "(ip[9] = 1"
				 " && "
				 "(icmp[0] = 0xb || icmp[0] = 0x3)  && icmp[12:2] = 0x%04x)",
				 g_ip4hdr_o.s_addr, g_ip4hdr_o.d_addr, g_d_port,
				 g_s_port, g_ip4hdr_o.id);
			break;
		case IPPROTO_UDP:
			snprintf(ufilter, 1024,
				 "dst host %s"
				 " && "
				 "(ip[9] = 17 && src host %s && src port 0x%x && dst port 0x%x)"
				 " || "
				 "(ip[9] = 1"
				 " && "
				 "(icmp[0] = 0xb || icmp[0] = 0x3)  && icmp[12:2] = 0x%04x)",
				 g_ip4hdr_o.s_addr, g_ip4hdr_o.d_addr, g_d_port,
				 g_s_port, g_ip4hdr_o.id);
			break;
		case IPPROTO_ICMP:
			snprintf(ufilter, 1024,
				 "dst host %s && ip[9] = 1"
				 " && "
				 "((icmp[0] = 0x0 && icmp[4:2] = 0x%04x && icmp[6:2] = 0x%04x)"
				 " || "
				 "((icmp[0] = 0xe || icmp[0] = 0x12) && icmp[4:2] = 0x%04x && icmp[6:2] = 0x%04x)"
				 " || "
				 "((icmp[0] = 0xb || icmp[0] = 0x3)  && icmp[12:2] = 0x%04x))",
				 g_ip4hdr_o.s_addr, htons(g_i4hdr_o.id),
				 htons(g_i4hdr_o.seqn), g_i4hdr_o.id,
				 g_i4hdr_o.seqn, g_ip4hdr_o.id);
			break;
		}
		g_filter = ufilter;
#ifdef DEBUG
		fprintf(stdout, "DEBUG: g_filter: %s\n", g_filter);
#endif
		if (pcap_compile(g_pkt, &bpf, g_filter, 0, netmask) < 0)
			fprintf(stderr,
				"\nWarning: Unable to compile packet filters: %s\n",
				pcap_geterr(g_pkt));
		if (pcap_setfilter(g_pkt, &bpf) < 0)
			fatal_error("Unable to set packet filters: %s",
				    pcap_geterr(g_pkt));
#ifdef HAVE_FREECODE
		pcap_freecode(&bpf);
#endif				/* HAVE_FREECODE */
		if ((d_link = pcap_datalink(g_pkt)) < 0)
			fatal_error("Unable to determine datalink type: %s",
				    pcap_geterr(g_pkt));
#ifdef SYSV_DERIVED
#ifdef HAVE_SETNONBLOCK
#ifdef DEBUG
		fprintf(stdout, "DEBUG: pcap_setnonblock()\n");
#endif				/* DEBUG */
		if (pcap_setnonblock(g_pkt, 1, error_buf) < 0)
			fatal_error("Unable to change to blocking mode: %s",
				    error_buf);
#else				/* HAVE_SETNONBLOCK */
		if (setnonblock(g_pkt, 1, error_buf) < 0)
			fatal_error("Unable to change to blocking mode: %s",
				    error_buf);
#endif				/* HAVE_SETNONBLOCK */
#endif				/* SYSV_DERIVED */
		print_separator(1, 2,
				(g_p_mode == M_TRACE) ? "HOP %d" : "SND %d",
				g_inj_cnt);
 start:
		if (!inject_packet())
			fatal_error("Unable to inject packet");
		gettimeofday(&g_bf_pcap, NULL);
		if (g_p_mode != M_TRACE) {
			print_ts(g_bf_pcap);
			print_injection_details();
		}
		g_hdr_len = retrieve_datalink_hdr_len(d_link);
#ifdef DEBUG
		fprintf(stdout, "DEBUG: start time: %ld.%ld\n",
			g_bf_pcap.tv_sec, g_bf_pcap.tv_usec);
		fprintf(stdout, "DEBUG: start dispatch loop\n");
#endif
		while (1) {
			dth_r =
			    pcap_dispatch(g_pkt, 1,
					  (pcap_handler) process_packets, NULL);
			if (dth_r < 0)
				fatal_error("Unable to inject packet");
			else if (dth_r > 0)
				break;
			gettimeofday(&g_af_pcap, NULL);
#ifdef DEBUG
			fprintf(stdout, "DEBUG: dispatch time: %ld.%ld\n",
				g_af_pcap.tv_sec, g_af_pcap.tv_usec);
#endif
			if (((g_af_pcap.tv_sec - g_bf_pcap.tv_sec) ==
			     g_r_timeout
			     && (g_bf_pcap.tv_usec < g_af_pcap.tv_usec))
			    || (g_af_pcap.tv_sec - g_bf_pcap.tv_sec) >
			    g_r_timeout) {
				if (g_p_mode == M_TRACE && tr_retry < 2) {
					tr_retry++;
					goto start;
				} else {
					tr_retry = 0;
					print_separator((g_p_mode ==
							 M_TRACE) ? 0 : 1, 1,
							"No Response From Peer");
					break;
				}
			}
			nanosleep(&n_sleep, NULL);
		}
#ifdef DEBUG
		fprintf(stdout, "DEBUG: dispatch loop complete\n");
#endif
		libnet_clear_packet(g_pkt_d);
		if (g_p_mode == M_TRACE) {
			if (g_tr_fin == 1)
				return FAILURE;
			else
				g_ip4hdr_o.ttl++;
		} else
		    if ((g_ip4hdr_o.p == IPPROTO_TCP
			 || g_ip4hdr_o.p == IPPROTO_UDP) && g_port_range)
			g_d_port++;
		else if (g_ip4hdr_o.p == IPPROTO_ICMP
			 && g_i4hdr_o.type == ICMP_ECHO)
			g_i4hdr_o.seqn++;
		if (g_burst_rate != 0 && g_p_mode != M_TRACE
		    && (g_inj_cnt % g_burst_rate) == 0 && i != g_cnt)
			sleep(g_interval_sec);
		g_inj_cnt++;
	}
	return FAILURE;
}

u_int16_t without_response(u_int32_t g_port_range)
{
	u_int64_t i;
	u_int32_t dstp = 0;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: without_response()\n");
#endif
	gettimeofday(&g_bf_pcap, NULL);
	if (g_cnt == 0)
		dstp = g_cnt = 1;
	for (i = 1; i < g_cnt + 1; i++) {
		if (dstp)
			i = 0;
		g_pkt_d = shape_packet();
		if (!inject_packet())
			fatal_error("Unable to inject packet");
		if (g_verbose) {
			print_separator(1, 2, "SND %ld", g_inj_cnt);
			print_injection_details();
			if (g_burst_rate != 0 && (g_inj_cnt % g_burst_rate) == 0
			    && i != g_cnt)
				sleep(g_interval_sec);
		} else {
			if (g_inj_cnt == 1) {
				fprintf(stdout, "\n");
				print_injection_details();
				if (dstp)
					fprintf(stderr,
						"\nWriting packet(s): ");
				else
					fprintf(stderr,
						"\nWriting packet(s) (%lu): ",
						g_cnt);
			}
			if (g_burst_rate != 0
			    && (g_inj_cnt % g_burst_rate) == 0) {
				fprintf(stderr, ".");
				if (i != g_cnt)
					sleep(g_interval_sec);
			}
		}
		gettimeofday(&g_af_pcap, NULL);
		libnet_clear_packet(g_pkt_d);
		if (g_ip4hdr_o.p == IPPROTO_ICMP && g_i4hdr_o.type == ICMP_ECHO) {
			g_i4hdr_o.seqn++;
		}
		if ((g_ip4hdr_o.p == IPPROTO_TCP ||
		     g_ip4hdr_o.p == IPPROTO_UDP) && g_port_range) {
			g_d_port++;
		}
		g_inj_cnt++;
	}
	return SUCCESS;
}
