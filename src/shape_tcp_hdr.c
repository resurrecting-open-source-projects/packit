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
shape_tcp_hdr(libnet_t *pkt_d)
{
    int flags = 0;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: shape_tcp_hdr()\n");
#endif

    hdr_len = TCP_H;

    if(rand_d_port)
        d_port = (unsigned short)retrieve_rand_int(P_UINT16); 

    if(rand_s_port)
        s_port = (unsigned short)retrieve_rand_int(P_UINT16);

    if((thdr_o.rand_seqn && thdr_o.syn) == 1)
        thdr_o.seqn =  (u_int32_t)retrieve_rand_int(P_INT32);

    flags = retrieve_tcp_flags(flags);

    if(libnet_build_tcp(
        s_port, 
        d_port, 
        thdr_o.seqn, 
        thdr_o.ackn, 
        flags, 
        thdr_o.win, 
        0, 
        thdr_o.urp, 
        hdr_len + payload_len, 
        payload, 
        payload_len, 
        pkt_d, 
        0) == -1)
    {
        fatal_error("Unable to build TCP header: %s", libnet_geterror(pkt_d)); 
    } 

    if(port_range)
        d_port++;

    return pkt_d;
}

int
parse_port_range(char *rangestr)
{
    unsigned short i, range = 0; 
    int spread[10];
    u_int8_t o_rangestr[11];
    u_int8_t *ptr, *delim = "-";

#ifdef DEBUG
    fprintf(stdout, "DEBUG: parse_port_range(): %s\n", rangestr);
#endif

    if(rangestr)
	strncpy(o_rangestr, rangestr, 11);

    for(i = 0, ptr = strtok(o_rangestr, delim);
        ptr;
        ptr = strtok(NULL, delim))
    {
	spread[i] = (int)atoi(ptr);

	if(spread[i] < 1 || spread[i] > 65535)
            return -1;

	i++;
    }

    rangestr = o_rangestr;
    range = spread[1] - spread[0] + 1;
    d_port = (unsigned short)spread[0];

    if(range < 1 || i != 2)
        return -1;

    return range;
}

