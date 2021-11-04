/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002 Darren Bounds <dbounds@intrusense.com>
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

#include "print_ethernet_hdr.h"

void print_ethernet_hdr(struct libnet_ethernet_hdr *ehdr)
{
#ifdef DEBUG
	fprintf(stdout, "DEBUG: print_ethernet_hdr()\n");
#endif
	fprintf(stdout,
		"Eth header:  Src Address: %0X:%0X:%0X:%0X:%0X:%0X  Dst Address: %0X:%0X:%0X:%0X:%0X:%0X",
		ehdr->ether_shost[0], ehdr->ether_shost[1],
		ehdr->ether_shost[2], ehdr->ether_shost[3],
		ehdr->ether_shost[4], ehdr->ether_shost[5],
		ehdr->ether_dhost[0], ehdr->ether_dhost[1],
		ehdr->ether_dhost[2], ehdr->ether_dhost[3],
		ehdr->ether_dhost[4], ehdr->ether_dhost[5]);
	fprintf(stdout, "\n");
}
