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
#include "../include/inject.h"
#include "../include/capture.h"
#include "../include/utils.h"
#include "../include/error.h"

void
injection_stats()
{
    u_int32_t tm_diff;

    struct libnet_stats ln_stats;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: injection_stats()\n");
#endif

    memset(&ln_stats, 0, sizeof(struct libnet_stats));

    print_separator((p_mode == M_INJECT_RESPONSE) ? 1 : 2, 1, "Packet Injection Statistics");

    libnet_stats(pkt_d, &ln_stats);

    if((tm_diff = af_pcap.tv_sec - bf_pcap.tv_sec) == 0)
        tm_diff = 1;

    if(p_mode == M_INJECT)
        fprintf(stdout, "Injected: %ld  Packets/Sec: %ld.%ld  Bytes/Sec: %ld.%ld  ", 
            ln_stats.packets_sent, 
            ln_stats.packets_sent / tm_diff, 
            ln_stats.packets_sent % tm_diff,
            ln_stats.bytes_written / tm_diff,
            ln_stats.bytes_written % tm_diff);
    else if(p_mode == M_INJECT_RESPONSE)
        fprintf(stdout, "Injected: %ld  Received: %d  Loss: %ld.%ld%%  Bytes Written: %ld  ", 
            ln_stats.packets_sent, cap_cnt, 
            100 - (cap_cnt * 100) / ln_stats.packets_sent,
            (cap_cnt * 100) % ln_stats.packets_sent,
            ln_stats.bytes_written);

    fprintf(stdout, "Errors: %ld",
        ln_stats.packet_errors);

    fprintf(stdout, "\n");

    return;
}

void
capture_stats()
{
    struct pcap_stat p_stats;

#ifdef DEBUG
    fprintf(stdout, "\nDEBUG: capture_stats()\n");
#endif

    memset(&p_stats, 0, sizeof(struct pcap_stat));

    pcap_stats(pkt, &p_stats);

    print_separator(0, 1, "Packet Capture Statistics");

    fprintf(stdout, "Received: %d  Dropped: %d  Processed: %d",
        p_stats.ps_recv, p_stats.ps_drop, inj_cnt);

    fprintf(stdout, "\n");

    return;
}

