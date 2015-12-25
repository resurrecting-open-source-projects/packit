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

void print_separator(int bnl, int anl, u_int8_t *msgp, ...);
u_int8_t *retrieve_rand_ipv4_addr();
u_int8_t *retrieve_rand_ethernet_addr();
u_int8_t *retrieve_arp_hw_type(u_int16_t hw_type);
u_int8_t *retrieve_arp_type(u_int16_t op_type);
u_int8_t *retrieve_icmp_type(u_int16_t type);
u_int8_t *retrieve_icmp_code(u_int16_t type, u_int16_t code);
u_int16_t retrieve_datalink_hdr_len(u_int32_t d_link);
u_int32_t retrieve_rand_int(u_int32_t r_size);


#endif /* __UTILS_H */
