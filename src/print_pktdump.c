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

#include <ctype.h>

#include "../include/packit.h"
#include "../include/capture.h"
#include "../include/error.h"

#define HEXDUMP_BYTES_PER_LINE 16
#define HEXDUMP_SHORTS_PER_LINE (HEXDUMP_BYTES_PER_LINE / 2)
#define HEXDUMP_HEXSTUFF_PER_SHORT 5 /* 4 hex digits and a space */
#define HEXDUMP_HEXSTUFF_PER_LINE \
            (HEXDUMP_HEXSTUFF_PER_SHORT * HEXDUMP_SHORTS_PER_LINE)

/*
 * This code was mostly taken from TCPdump :)
 */
     
void
print_packet_hexdump(u_int8_t *cp, int len)
{
    int i, offset, nshorts, s1, s2;
    char hex_data[HEXDUMP_SHORTS_PER_LINE*HEXDUMP_HEXSTUFF_PER_SHORT+1], *hsp;
    char ascii_data[HEXDUMP_BYTES_PER_LINE+1], *asp;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: print_packet_hexdump()\n");
#endif

    offset = i = 0;
    hsp = hex_data; 
    asp = ascii_data;
    nshorts = len / sizeof(u_int16_t);

    while (--nshorts >= 0) 
    {
        s1 = *cp++;
        s2 = *cp++;
        
        snprintf(hsp,
            sizeof(hex_data) - (hsp - hex_data),
            " %02x%02x", 
            s1, 
            s2);
        
        hsp += HEXDUMP_HEXSTUFF_PER_SHORT;
        
        *(asp++) = (isgraph(s1) ? s1 : '-');
        *(asp++) = (isgraph(s2) ? s2 : '-');
        
        if(++i >= HEXDUMP_SHORTS_PER_LINE) 
        {
            *hsp = *asp = '\0';
            
            fprintf(stdout, "\n0x%04x\t    %-*s\t   %s",
                offset, 
                HEXDUMP_HEXSTUFF_PER_LINE,
                hex_data, 
                ascii_data);
            
            i = 0; 
            hsp = hex_data; 
            asp = ascii_data;
            offset += HEXDUMP_BYTES_PER_LINE;
        }
    }

    if(len & 1) 
    {
        s1 = *cp++;
            
        snprintf(hsp, 
            sizeof(hex_data) - (hsp - hex_data),
            " %02x", 
            s1);
	
        hsp += 3;
        *(asp++) = (isgraph(s1) ? s1 : '.');
        ++i;
    }
    
    if(i > 0) 
    {
        *hsp = *asp = '\0';
        
        fprintf(stdout, "\n0x%04x\t    %-*s\t   %s",
            offset, 
            HEXDUMP_HEXSTUFF_PER_LINE,
            hex_data, 
            ascii_data);
    }

    fprintf(stdout, "\n");

    return;
}
