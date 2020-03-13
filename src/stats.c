/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2017 Robert Krause <ruport@f00l.de>
 * Copyright 2017 Sharad B
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

#include "stats.h"

void injection_stats()
{
	u_int32_t tm_diff;
	struct libnet_stats ln_stats;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: injection_stats()\n");
#endif
	memset(&ln_stats, 0, sizeof(struct libnet_stats));
	if (g_p_mode == M_TRACE)
		print_separator(1, 1, "Trace Route Statistics");
	else
		print_separator((g_p_mode == M_INJECT_RESPONSE) ? 1 : 2, 1,
				"Packet Injection Statistics");
	libnet_stats(g_pkt_d, &ln_stats);
	if ((tm_diff = g_af_pcap.tv_sec - g_bf_pcap.tv_sec) == 0)
		tm_diff = 1;
	if (g_p_mode == M_INJECT)
		fprintf(stdout,
			"Injected: %lu  Packets/Sec: %lu.%lu  Bytes/Sec: %lu.%lu  ",
			(u_int64_t) ln_stats.packets_sent,
			(u_int64_t) ln_stats.packets_sent / tm_diff,
			(u_int64_t) ln_stats.packets_sent % tm_diff,
			(u_int64_t) ln_stats.bytes_written / tm_diff,
			(u_int64_t) ln_stats.bytes_written % tm_diff);
	else if (g_p_mode == M_INJECT_RESPONSE) {
		fprintf(stdout,
			"Injected: %lu  Received: %lu  Loss: %lu.%lu%%  Bytes Written: %lu  ",
			(u_int64_t) ln_stats.packets_sent, g_cap_cnt,
			(u_int64_t) (ln_stats.packets_sent ==
				     0) ? 0 : (100 -
					       (g_cap_cnt * 100) /
					       ln_stats.packets_sent),
			(u_int64_t) (g_cap_cnt * 100) % ln_stats.packets_sent,
			(u_int64_t) ln_stats.bytes_written);
	} else if (g_p_mode == M_TRACE)
		fprintf(stdout,
			"Hop Count: %lu  Responses: %lu  Bytes Written: %lu  ",
			g_inj_cnt, g_cap_cnt,
			(u_int64_t) ln_stats.bytes_written);
	fprintf(stdout, "Errors: %lu", (u_int64_t) ln_stats.packet_errors);
	fprintf(stdout, "\n");
}

void capture_stats()
{
	struct pcap_stat p_stats;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: capture_stats()\n");
#endif
	memset(&p_stats, 0, sizeof(struct pcap_stat));
	pcap_stats(g_pkt, &p_stats);
	print_separator(0, 1, "Packet Capture Statistics");
	fprintf(stdout, "Received: %u  Dropped: %u  Processed: %lu",
		p_stats.ps_recv, p_stats.ps_drop, g_inj_cnt);
	fprintf(stdout, "\n");
}
