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

#include "print_arp_hdr.h"

void 
print_arp_hdr(u_int8_t *packet)
{
    u_int8_t *arp_t, *arp_hw_t;
    
    struct libnet_arp_hdr *ahdr;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: print_arp_hdr()\n");
#endif

    ahdr = (struct libnet_arp_hdr *)(packet + hdr_len);

    arp_t = retrieve_arp_type(htons(ahdr->ar_op));
    arp_hw_t = retrieve_arp_hw_type(htons(ahdr->ar_hrd));

    fprintf(stdout, "ARP header:  Type: %s(%d)\n", arp_t, htons(ahdr->ar_op));
    fprintf(stdout, "\t     Hardware Format: %s  Length: %d\n", 
        arp_hw_t, 
	ahdr->ar_hln);
    
    fprintf(stdout, "\t     Protocol Format: %d  Length: %d\n", 
        ahdr->ar_pro, 
	ahdr->ar_pln);

    return;
}
