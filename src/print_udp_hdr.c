/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002 Darren Bounds <dbounds@intrusense.com>
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
 * packit official page at https://github.com/eribertomota/packit
 */

#include "print_udp_hdr.h"

void
print_udp_hdr(u_int8_t *packet)
{
    struct libnet_udp_hdr *udphdr;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: print_udp_hdr()\n");
#endif

    udphdr = (struct libnet_udp_hdr *)(packet + IPV4_H + g_hdr_len);

    fprintf(stdout, "UDP header:  Src Port: %d  Dst Port: %d  Len: %d  ",
        htons(udphdr->uh_sport),
        htons(udphdr->uh_dport),
        ntohs(udphdr->uh_ulen));

    fprintf(stdout, "\n");

    return;
}

