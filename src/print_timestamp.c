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
#include "../include/capture.h"
#include "../include/error.h"

#define TIMESTAMP_BUF_MAX 	64

void 
print_timestamp(struct timeval ts)
{
    char timestamp[TIMESTAMP_BUF_MAX];

    struct tm *ltm;
    struct timeval tv;
    struct timeval *tvp;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: print_timestamp()\n");
#endif

    ltm = malloc(sizeof(struct tm));
    memset(ltm, 0, sizeof(struct tm));

    memset(&tv, 0, sizeof(struct timeval));

    tvp = malloc(sizeof(struct timeval));
    memset(tvp, 0, sizeof(struct timeval));

    if(time_gmt)
    {
        snprintf(timestamp, TIMESTAMP_BUF_MAX, "%02lu:%02lu:%02lu.%06lu",
            (unsigned long)(ts.tv_sec % 86400) / 3600,
	    (unsigned long)((ts.tv_sec % 86400) % 3600) / 60,
            (unsigned long)(ts.tv_sec % 86400) % 40,
            (unsigned long)ts.tv_usec);
    }
    else
    {
	tvp = &tv;

        gettimeofday(tvp, NULL);
        ltm = localtime((time_t *) & tvp->tv_sec);

        snprintf(timestamp, TIMESTAMP_BUF_MAX, "%02lu:%02lu:%02lu.%06lu",
	    (unsigned long)ltm->tm_hour,
	    (unsigned long)ltm->tm_min,
	    (unsigned long)ltm->tm_sec,
	    (unsigned long)ts.tv_usec);
    }

    fprintf(stdout, "Timestamp:   %s\n", timestamp);

    return;
}
