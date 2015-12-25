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

#ifndef __INJECTION_H
#define __INJECTION_H

#include "globals.h"
#include "inject_defs.h"
#include "capture.h"
#include "capture_defs.h"
#include "shape_packet.h"
#include "print_injection.h"
#include "print_ts.h"

void injection_init();
u_int16_t inject_packet();
u_int16_t with_response();
u_int16_t without_response();
int setnonblock(pcap_t *, int, char *);

#endif /* __INJECTION_H */
