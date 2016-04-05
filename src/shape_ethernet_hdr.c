/*
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2013      Mats Erik Andersson <gnu@gisladisker.se>
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
 *
 */

#include "shape_ethernet_hdr.h"

libnet_t *
shape_ethernet_hdr(libnet_t *pkt_d)
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

    if(ehdr_o.rand_s_addr)
        ehdr_o.s_addr = retrieve_rand_ethernet_addr(ehdr_o.s_addr);

    if(ehdr_o.rand_d_addr)
        ehdr_o.d_addr = retrieve_rand_ethernet_addr(ehdr_o.d_addr);

    if(ehdr_o.s_addr == NULL)
    {
        if((hw_addr = libnet_get_hwaddr(pkt_d)) == NULL)
            fatal_error("Unable to determine ethernet address: %s", libnet_geterror(pkt_d));

	for(i = 0; i < 6; i++)
	    us_addr[i] = hw_addr->ether_addr_octet[i];
    }
    else
        if(format_ethernet_addr(ehdr_o.s_addr, us_addr) == 0)
            fatal_error("Invalid source ethernet address");
    
    snprintf(ehdr_o.shw_addr, 18, "%0X:%0X:%0X:%0X:%0X:%0X",
        us_addr[0], us_addr[1], us_addr[2], us_addr[3], us_addr[4], us_addr[5]);

    if(ehdr_o.d_addr == NULL
       && (injection_type == ETHERTYPE_ARP || injection_type == ETHERTYPE_REVARP))
	ehdr_o.d_addr = ETH_BROADCAST; 
    else
    if(ehdr_o.d_addr == NULL)
    {
	fprintf(stderr, "Warning: Using NULL destination ethernet address. Packets may not reach their destination\n");
        ehdr_o.d_addr = ETH_DEFAULT;
    }

    if(format_ethernet_addr(ehdr_o.d_addr, ud_addr) == 0)
        fatal_error("Invalid destination ethernet address");

    snprintf(ehdr_o.dhw_addr, 18, "%0X:%0X:%0X:%0X:%0X:%0X",
        ud_addr[0], ud_addr[1], ud_addr[2], ud_addr[3], ud_addr[4], ud_addr[5]);

    if(libnet_build_ethernet(
        ud_addr,
        us_addr,
        injection_type,
        NULL,
        0,
        pkt_d,
        0) == -1)
    {
        fatal_error("Unable to build ethernet header");
    }

    return pkt_d;
}

libnet_t *
shape_ethernet_hdr_auto(libnet_t *pkt_d, u_int16_t type)
{
    u_int8_t d_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

#ifdef DEBUG
    fprintf(stdout, "DEBUG: shape_ethernet_hdr_auto()\n");
#endif

    if(libnet_autobuild_ethernet(
        d_addr,                 
        type,
        pkt_d) == -1)
    {
        fatal_error("Unable to auto-build ethernet header");
    }
		
    return pkt_d;
}
