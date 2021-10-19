/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2004      Dennis Vshivkov <walrus@amur.ru>
 * Copyright 2013      Mats Erik Andersson <gnu@gisladisker.se>
 * Copyright 2017      Robert Krause <ruport@f00l.de>
 * Copyright 2017      Sharad B
 * Copyright 2020      David Polverari <david.polverari@gmail.com>
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

#include "error.h"
#include "inject_defs.h"
#include "shape_ethernet_hdr.h"
#include "utils.h"
#include "globals.h"

libnet_t *shape_ethernet_hdr(libnet_t * g_pkt_d)
{
	int i;
	u_int8_t us_addr[6];
	u_int8_t ud_addr[6];
	struct libnet_ether_addr *hw_addr;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: shape_ethernet_hdr()\n");
#endif
	hw_addr = malloc(sizeof(struct libnet_ether_addr));
	memset(hw_addr, 0, sizeof(struct libnet_ether_addr));
	if (g_ehdr_o.rand_s_addr)
		g_ehdr_o.s_addr = retrieve_rand_ethernet_addr(g_ehdr_o.s_addr);
	if (g_ehdr_o.rand_d_addr)
		g_ehdr_o.d_addr = retrieve_rand_ethernet_addr(g_ehdr_o.d_addr);
	if (g_ehdr_o.s_addr == NULL) {
		if ((hw_addr = libnet_get_hwaddr(g_pkt_d)) == NULL)
			fatal_error("Unable to determine ethernet address: %s",
				    libnet_geterror(g_pkt_d));
		for (i = 0; i < 6; i++)
			us_addr[i] = hw_addr->ether_addr_octet[i];
	} else if (format_ethernet_addr(g_ehdr_o.s_addr, us_addr) == 0)
		fatal_error("Invalid source ethernet address");
	snprintf((char *)g_ehdr_o.shw_addr, 18, "%0X:%0X:%0X:%0X:%0X:%0X",
		 us_addr[0], us_addr[1], us_addr[2], us_addr[3], us_addr[4],
		 us_addr[5]);
	if (g_ehdr_o.d_addr == NULL
	    && (g_injection_type == ETHERTYPE_ARP
		|| g_injection_type == ETHERTYPE_REVARP)) {
		g_ehdr_o.d_addr = (u_int8_t *) ETH_BROADCAST;
	} else if (g_ehdr_o.d_addr == NULL) {
		fprintf(stderr,
			"Warning: Using NULL destination ethernet address. Packets may not reach their destination\n");
		g_ehdr_o.d_addr = (u_int8_t *) ETH_DEFAULT;
	}
	if (format_ethernet_addr(g_ehdr_o.d_addr, ud_addr) == 0)
		fatal_error("Invalid destination ethernet address");
	snprintf((char *)g_ehdr_o.dhw_addr, 18, "%0X:%0X:%0X:%0X:%0X:%0X",
		 ud_addr[0], ud_addr[1], ud_addr[2], ud_addr[3], ud_addr[4],
		 ud_addr[5]);
	if ((g_ehdr_o.dot1q_vlan_id_cpi_prio == 0
				? libnet_build_ethernet(
					ud_addr,
					us_addr,
					g_injection_type,
					NULL,
					0,
					g_pkt_d,
					0)
				: libnet_build_802_1q(
					ud_addr,
					us_addr,
					ETHERTYPE_VLAN,
					g_ehdr_o.dot1q_vlan_id_cpi_prio >> 13,		/* priority */
					(g_ehdr_o.dot1q_vlan_id_cpi_prio >> 12) & 1,	/* cpi */
					g_ehdr_o.dot1q_vlan_id_cpi_prio & 0xFFF,	/* id */
					g_injection_type,
					NULL,
					0,
					g_pkt_d,
					0)) == -1) {
		fatal_error("Unable to build ethernet header");
	}
	return g_pkt_d;
}

libnet_t *shape_ethernet_hdr_auto(libnet_t * g_pkt_d, u_int16_t type)
{
	u_int8_t d_addr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#ifdef DEBUG
	fprintf(stdout, "DEBUG: shape_ethernet_hdr_auto()\n");
#endif
	if (libnet_autobuild_ethernet(d_addr, type, g_pkt_d) == -1) {
		fatal_error("Unable to auto-build ethernet header");
	}
	return g_pkt_d;
}
