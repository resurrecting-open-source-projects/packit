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

#include "shape_arp_hdr.h"

libnet_t *shape_arp_hdr(libnet_t * g_pkt_d)
{
	u_int32_t i, s_paddr, r_paddr;
	u_int8_t s_neaddr[6];
	u_int8_t r_neaddr[6];
	struct libnet_ether_addr *hw_addr;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: shape_arp_hdr()\n");
#endif
	hw_addr = malloc(sizeof(struct libnet_ether_addr));
	memset(hw_addr, 0, sizeof(struct libnet_ether_addr));
	s_paddr = r_paddr = 0;
	if (g_ahdr_o.rand_s_paddr)
		g_ahdr_o.s_paddr = retrieve_rand_ipv4_addr(g_ahdr_o.s_paddr);
	if (g_ahdr_o.rand_r_paddr)
		g_ahdr_o.r_paddr = retrieve_rand_ipv4_addr(g_ahdr_o.r_paddr);
	if (g_ahdr_o.rand_s_eaddr)
		g_ahdr_o.s_eaddr =
		    retrieve_rand_ethernet_addr(g_ahdr_o.s_eaddr);
	if (g_ahdr_o.rand_r_eaddr)
		g_ahdr_o.r_eaddr =
		    retrieve_rand_ethernet_addr(g_ahdr_o.r_eaddr);
	if (g_ahdr_o.s_paddr == NULL) {
		switch (g_ahdr_o.op_type) {
		case ARPOP_REQUEST:
		case ARPOP_REVREQUEST:
			if ((s_paddr = libnet_get_ipaddr4(g_pkt_d)) == -1)
				fatal_error
				    ("Unable to retrieve local IP address: %s",
				     libnet_geterror(g_pkt_d));
			g_ahdr_o.s_paddr =
			    (u_int8_t *) libnet_addr2name4(s_paddr, 0);
			break;
		default:
			g_ahdr_o.s_paddr = IPV4_DEFAULT;
			break;
		}
	}
	if ((s_paddr =
	     libnet_name2addr4(g_pkt_d, (char *)g_ahdr_o.s_paddr, 0)) == -1)
		fatal_error("Invalid sender protocol address: %s",
			    g_ahdr_o.s_paddr);
	if (g_ahdr_o.s_eaddr == NULL) {
		switch (g_ahdr_o.op_type) {
		case ARPOP_REQUEST:
		case ARPOP_REVREQUEST:
			if ((hw_addr = libnet_get_hwaddr(g_pkt_d)) == NULL)
				fatal_error
				    ("Unable to determine ethernet address: %s",
				     libnet_geterror(g_pkt_d));
			for (i = 0; i < 6; i++)
				s_neaddr[i] = hw_addr->ether_addr_octet[i];
			break;
		default:
			g_ahdr_o.s_eaddr = (u_int8_t *) ETH_DEFAULT;
			break;
		}
	}
	if (format_ethernet_addr(g_ahdr_o.s_eaddr, s_neaddr) == 0)
		fatal_error("Invalid sender ethernet address");
	snprintf((char *)g_ahdr_o.shw_addr, 18, "%0X:%0X:%0X:%0X:%0X:%0X",
		 s_neaddr[0], s_neaddr[1], s_neaddr[2], s_neaddr[3],
		 s_neaddr[4], s_neaddr[5]);
	if (g_ahdr_o.r_paddr == NULL) {
		switch (g_ahdr_o.op_type) {
		case ARPOP_REPLY:
		case ARPOP_REQUEST:
			if ((r_paddr = libnet_get_ipaddr4(g_pkt_d)) == -1)
				fatal_error
				    ("Unable to retrieve local IP address: %s",
				     libnet_geterror(g_pkt_d));
			g_ahdr_o.r_paddr =
			    (u_int8_t *) libnet_addr2name4(r_paddr, 0);
			break;
		default:
			g_ahdr_o.r_paddr = IPV4_DEFAULT;
			break;
		}
	}
	if ((r_paddr =
	     libnet_name2addr4(g_pkt_d, (char *)g_ahdr_o.r_paddr, 0)) == -1)
		fatal_error("Invalid receiver protocol address: %s",
			    g_ahdr_o.r_paddr);
	if (g_ahdr_o.r_eaddr == NULL) {
		switch (g_ahdr_o.op_type) {
		case ARPOP_REPLY:
		case ARPOP_REVREPLY:
			if ((hw_addr = libnet_get_hwaddr(g_pkt_d)) == NULL)
				fatal_error
				    ("Unable to determine ethernet address: %s",
				     libnet_geterror(g_pkt_d));
			for (i = 0; i < 6; i++)
				r_neaddr[i] = hw_addr->ether_addr_octet[i];
			break;
		default:
			g_ahdr_o.r_eaddr = (u_int8_t *) ETH_DEFAULT;
			break;
		}
	}
	if (format_ethernet_addr(g_ahdr_o.r_eaddr, r_neaddr) == 0)
		fatal_error("Invalid receiver ethernet address");
	snprintf((char *)g_ahdr_o.rhw_addr, 18, "%0X:%0X:%0X:%0X:%0X:%0X",
		 r_neaddr[0], r_neaddr[1], r_neaddr[2], r_neaddr[3],
		 r_neaddr[4], r_neaddr[5]);
	if (libnet_build_arp(ARPHRD_ETHER,
			     ETHERTYPE_IP,
			     6,
			     4,
			     g_ahdr_o.op_type,
			     s_neaddr,
			     (u_int8_t *) & s_paddr,
			     r_neaddr,
			     (u_int8_t *) & r_paddr,
			     g_payload, g_payload_len, g_pkt_d, 0) == -1) {
		fatal_error("Unable to build ARP header: %s",
			    libnet_geterror(g_pkt_d));
	}
	return g_pkt_d;
}
