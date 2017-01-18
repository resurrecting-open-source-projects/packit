/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2017 Sharad B
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
 */

#ifndef __CAPTURE_DEFS_H
#define __CAPTURE_DEFS_H

#define READ_TIMEOUT                    500
#define SNAPLEN_DEFAULT                 68

u_int16_t g_display;
u_int16_t g_link_layer;
u_int16_t g_dump_pkt;
u_int16_t g_time_gmt;
u_int16_t g_t_rst;
u_int16_t g_snap_len;
u_int32_t g_pkt_rst;

#endif /* __CAPTURE_DEFS_H */
