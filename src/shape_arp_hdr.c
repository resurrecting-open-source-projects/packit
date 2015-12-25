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
shape_arp_hdr(libnet_t *pkt_d)
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

    if(ahdr_o.rand_s_paddr)
        ahdr_o.s_paddr = retrieve_rand_ipv4_addr();

    if(ahdr_o.rand_r_paddr)
        ahdr_o.r_paddr = retrieve_rand_ipv4_addr();

    if(ahdr_o.rand_s_eaddr)
        ahdr_o.s_eaddr = retrieve_rand_ethernet_addr();

    if(ahdr_o.rand_r_eaddr)
        ahdr_o.r_eaddr = retrieve_rand_ethernet_addr();

    if(ahdr_o.s_paddr == NULL)
    {
	switch(ahdr_o.op_type)
	{
            case ARPOP_REQUEST: case ARPOP_REVREQUEST:
                if((s_paddr = libnet_get_ipaddr4(pkt_d)) == -1)
                {
                    fatal_error("Unable to retrieve local IP address: %s", libnet_geterror(pkt_d));
                }
	    
                ahdr_o.s_paddr = libnet_addr2name4(s_paddr, 0);
		break;
		
	    default:
                ahdr_o.s_paddr = IPV4_DEFAULT; 
		break;
	}
    }
	
    if((s_paddr = libnet_name2addr4(pkt_d, ahdr_o.s_paddr, 0)) == -1)
        fatal_error("Invalid sender protocol address: %s", ahdr_o.s_paddr);

    if(ahdr_o.s_eaddr == NULL)
    {
	switch(ahdr_o.op_type)
	{
	    case ARPOP_REQUEST: case ARPOP_REVREQUEST: 
                if((hw_addr = libnet_get_hwaddr(pkt_d)) == NULL)
                    fatal_error("Unable to determine ethernet address: %s", libnet_geterror(pkt_d));

                for(i = 0; i < 6; i++)
                    s_neaddr[i] = hw_addr->ether_addr_octet[i];

		break;

	    default:
                ahdr_o.s_eaddr = ETH_DEFAULT;
                break;
        }
    }
    
    if(format_ethernet_addr(ahdr_o.s_eaddr, s_neaddr) == 0)
        fatal_error("Invalid sender ethernet address");

    snprintf(ahdr_o.shw_addr, 18, "%0X:%0X:%0X:%0X:%0X:%0X",
        s_neaddr[0], s_neaddr[1], s_neaddr[2], s_neaddr[3], s_neaddr[4], s_neaddr[5]);

    if(ahdr_o.r_paddr == NULL)
    {
	switch(ahdr_o.op_type)
	{
	    case ARPOP_REPLY: case ARPOP_REQUEST:
                if((r_paddr = libnet_get_ipaddr4(pkt_d)) == -1)
	            fatal_error("Unable to retrieve local IP address: %s", libnet_geterror(pkt_d));

                ahdr_o.r_paddr = libnet_addr2name4(r_paddr, 0);
		break;
	 
	    default:
		ahdr_o.r_paddr = IPV4_DEFAULT; 
		break;
	}
    }
   
    if((r_paddr = libnet_name2addr4(pkt_d, ahdr_o.r_paddr, 0)) == -1)
        fatal_error("Invalid receiver protocol address: %s", ahdr_o.r_paddr);

    if(ahdr_o.r_eaddr == NULL)
    {
        switch(ahdr_o.op_type)
        {
            case ARPOP_REPLY: case ARPOP_REVREPLY:
                if((hw_addr = libnet_get_hwaddr(pkt_d)) == NULL)
	            fatal_error("Unable to determine ethernet address: %s", libnet_geterror(pkt_d));


                for(i = 0; i < 6; i++)
                    r_neaddr[i] = hw_addr->ether_addr_octet[i];

		break;

	    default:
                ahdr_o.r_eaddr = ETH_DEFAULT;
		break;
	}
    }

    if(format_ethernet_addr(ahdr_o.r_eaddr, r_neaddr) == 0)
        fatal_error("Invalid receiver ethernet address");

    snprintf(ahdr_o.rhw_addr, 18, "%0X:%0X:%0X:%0X:%0X:%0X",
        r_neaddr[0], r_neaddr[1], r_neaddr[2], r_neaddr[3], r_neaddr[4], r_neaddr[5]);

    if(libnet_build_arp(
        ARPHRD_ETHER,                    
        ETHERTYPE_IP,                          
        6,                                      
        4,                                      
        ahdr_o.op_type,                     
        s_neaddr,                           
        (u_int8_t *)&s_paddr,                          
        r_neaddr,                          
        (u_int8_t *)&r_paddr,                          
        payload,                                   
        payload_len,                                     
        pkt_d,                                      
        0) == -1)                              
    {
        fatal_error("Unable to build ARP header: %s", libnet_geterror(pkt_d)); 
    } 

    return pkt_d;
}
