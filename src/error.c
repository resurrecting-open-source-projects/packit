/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2016 Robert Krause <ruport@f00l.de>
 * Copyright 2020 Jeroen Roovers <jer@gentoo.org>
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

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

#include "error.h"

char error_buf[ERRBUF_MAXLEN];

void fatal_error(char *err, ...)
{
	va_list va;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: fatal_error()\n");
#endif
	va_start(va, err);
	vsnprintf(error_buf, ERRBUF_MAXLEN, err, va);
	va_end(va);
	fprintf(stderr, "\nError: %s\n", error_buf);
	exit(EXIT_FAILURE);
}
