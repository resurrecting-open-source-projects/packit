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

#ifndef __UTILS_H
#define __UTILS_H

#include "globals.h"
#include "inject_defs.h"
#include "capture_defs.h"
#include "pcap.h"

void print_separator(int, int, u_int8_t *, ...);
u_int8_t *retrieve_rand_ipv4_addr(u_int8_t *);
u_int8_t *retrieve_rand_ethernet_addr(u_int8_t *);
u_int8_t *retrieve_arp_hw_type(u_int16_t);
u_int8_t *retrieve_arp_type(u_int16_t);
u_int8_t *retrieve_icmp_type(u_int16_t);
u_int8_t *retrieve_icmp_code(u_int16_t, u_int16_t);
u_int8_t *generate_padding(u_int16_t, u_int16_t);
u_int32_t format_hex_payload(u_int8_t *);
u_int16_t parse_port_range(u_int8_t *);
u_int16_t retrieve_datalink_hdr_len(u_int32_t);
u_int32_t retrieve_rand_int(u_int32_t);
u_int32_t format_ethernet_addr(char *, u_int8_t[]);
int retrieve_tcp_flags();

#endif /* __UTILS_H */

