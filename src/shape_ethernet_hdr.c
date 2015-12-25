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
#include "../include/utils.h"
#include "../include/error.h"


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

    if(ehdr_o.eh_rand_s_addr)
        ehdr_o.s_addr = retrieve_rand_ethernet_addr();

    if(ehdr_o.eh_rand_d_addr)
        ehdr_o.d_addr = retrieve_rand_ethernet_addr();

    if(ehdr_o.s_addr == NULL)
    {
        if((hw_addr = libnet_get_hwaddr(pkt_d)) == NULL)
            fatal_error("Unable to determine ethernet address: %s", libnet_geterror(pkt_d));

	for(i = 0; i < 6; i++)
	    us_addr[i] = hw_addr->ether_addr_octet[i];
    }
    else
    {
        if(format_ethernet_addr(ehdr_o.s_addr, us_addr) == 0)
            fatal_error("Invalid source ethernet address");
    }
    
    snprintf(ehdr_o.shw_addr, 18, "%0X:%0X:%0X:%0X:%0X:%0X",
        us_addr[0], us_addr[1], us_addr[2], us_addr[3], us_addr[4], us_addr[5]);

    if(ehdr_o.d_addr == NULL && injection_type == ETHERTYPE_ARP)
	ehdr_o.d_addr = ETH_BROADCAST; 
    else if(ehdr_o.d_addr == NULL)
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
        fatal_error("Unable to build Ethernet header");
    }

    return pkt_d;
}

libnet_t *
shape_ethernet_hdr_auto(libnet_t *pkt_d)
{
    u_int8_t d_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

#ifdef DEBUG
    fprintf(stdout, "DEBUG: shape_ethernet_hdr_auto()\n");
#endif

    if(libnet_autobuild_ethernet(
        d_addr,                 
        ETHERTYPE_ARP, 
        pkt_d) == -1)
    {
	fatal_error("Unable to auto build Ethernet header");
    }
		
    return pkt_d;
}

int
format_ethernet_addr(char *ethstr, u_int8_t u_eaddr[6])
{
    int i = 0;
    long base16;
    u_int8_t *eptr, *delim = ":";
    u_int8_t o_ethstr[18] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}; 
   
#ifdef DEBUG
    fprintf(stdout, "DEBUG: format_ethernet_addr()\n");
#endif

    if(ethstr)
    {
	strncpy(o_ethstr, ethstr, 18);
    }
    else
    {
	u_eaddr = o_ethstr;
        return 1;
    }

    for(eptr = strtok(o_ethstr, delim);
         eptr;
         eptr = strtok(NULL, delim))
    {
        if((base16 = strtol(eptr, 0, 16)) > 0xff)
	    return 0;	

        u_eaddr[i] = base16;
        i++;
    }

    if(i != 6)
        return 0;    

    ethstr = o_ethstr;

    return 1; 
}
