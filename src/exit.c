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
#include "../include/capture.h"
#include "../include/utils.h"
#include "../include/error.h"

void
injection_clean_exit(int sig)
{
    u_int8_t a[2];

#ifdef DEBUG
    fprintf(stdout, "DEBUG: injection_clean_exit(%d)\n", sig);
#endif

    if(sig == SIGINT)
    {
        while(1)
        {
            fprintf(stdout, "\n\nWould you like to quit? (y/n): ");
            fread(a, 2, 1, stdin);
            fflush(stdout);

            if(!strncasecmp(a, "Y", 1))            
                break;
            else if(!strncasecmp(a, "N", 1))
                return;
        }
    }

    injection_stats();
    libnet_destroy(pkt_d);

    fprintf(stdout, "\n");

#ifdef DEBUG
    fprintf(stdout, "DEBUG: Good-Bye\n");
#endif

    exit(SUCCESS);

    return;
}

void
capture_clean_exit(int sig)
{
#ifdef DEBUG
    fprintf(stdout, "\nDEBUG: capture_clean_exit() SIG: %d\n", sig);
#endif

    fprintf(stdout, "\n");

    capture_stats();
    pcap_close(pkt);

    fprintf(stdout, "\n");

    exit(SUCCESS);

    return;
}
