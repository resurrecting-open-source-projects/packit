/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2017 Sharad B
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

#include "print_ts.h"

void print_ts(struct timeval ts)
{
	char timestamp[TIMESTAMP_MAXLEN];

	struct tm *ltm;
	struct timeval tv, *tvp;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: print_ts()\n");
#endif
	ltm = malloc(sizeof(struct tm));
	memset(ltm, 0, sizeof(struct tm));
	memset(&tv, 0, sizeof(struct timeval));
	tvp = malloc(sizeof(struct timeval));
	memset(tvp, 0, sizeof(struct timeval));
	if (g_time_gmt)
		snprintf(timestamp, TIMESTAMP_MAXLEN, "%02lu:%02lu:%02lu.%06lu",
			 (u_long) (ts.tv_sec % 86400) / 3600,
			 (u_long) ((ts.tv_sec % 86400) % 3600) / 60,
			 (u_long) (ts.tv_sec % 86400) % 40,
			 (u_long) ts.tv_usec);
	else {
		tvp = &tv;
		gettimeofday(tvp, NULL);
		ltm = localtime((time_t *) & tvp->tv_sec);
		snprintf(timestamp, TIMESTAMP_MAXLEN, "%02lu:%02lu:%02lu.%06lu",
			 (u_long) ltm->tm_hour,
			 (u_long) ltm->tm_min,
			 (u_long) ltm->tm_sec, (u_long) ts.tv_usec);
	}
	fprintf(stdout, "Timestamp:   %s\n", timestamp);
}
