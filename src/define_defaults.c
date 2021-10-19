/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2015      Gentoo Linux
 * Copyright 2017      Robert Krause <ruport@f00l.de>
 * Copyright 2017      Sharad B
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

#include "globals.h"
#include "injection.h"
#include "inject_defs.h"
#include "define_defaults.h"
#include "capture_defs.h"

void define_injection_defaults()
{
	g_cnt = (g_p_mode == M_INJECT) ? 1 : 30;
	g_inj_cnt = 1;
	g_cap_cnt = 0;
	g_rawip = 0;
	g_s_port = 0;
	g_rand_s_port = 1;

	// g_s_d_port = "0";
	g_s_d_port = malloc(4);
	strcpy((char *)g_s_d_port, "0");

	g_d_port = 0;
	g_rand_d_port = (g_p_mode == M_TRACE) ? 1 : 0;
	g_r_timeout = 1;
	g_burst_rate = 1;
	g_init_type = 1;
	g_interval_sec = 1;
	g_interval_usec = 0;
	g_payload = NULL;
	g_payload_len = 0;
	g_hdr_len = 0;
	g_display = 1;
	g_verbose = 0;
	g_resolve = 1;
	g_link_layer = 0;
	g_resolve = 0;
}
