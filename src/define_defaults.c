/*
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2015      Gentoo Linux
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
 * packit official page at https://github.com/eribertomota/packit
 *
 */

#include "define_defaults.h"

void
define_injection_defaults()
{
    cnt = (p_mode == M_INJECT) ? 1 : 30;
    inj_cnt = 1;
    cap_cnt = 0;
    rawip = 0; 
    s_port = 0;
    rand_s_port = 1;
    s_d_port = "0";
    d_port = 0;
    rand_d_port = (p_mode == M_TRACE) ? 1 : 0;
    r_timeout = 1;
    burst_rate = 1;
    init_type = 1;
    interval_sec = 1;
    interval_usec = 0;
    payload = NULL;
    payload_len = 0;
    hdr_len = 0;
    display = 1;
    verbose = 0;
    resolve = 1;
    link_layer = 0;
    resolve = 0;

    return;
}
