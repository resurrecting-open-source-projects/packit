# Packit -- network injection and capture tool
#
# Original author: Darren Bounds <dbounds@intrusense.com>
#
# Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
# Copyright 2007      LaMont Jones <lamont@debian.org>
# Copyright 2016      Joao Eriberto Mota Filho <eriberto@eriberto.pro.br>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.
#
# packit official page at https://github.com/eribertomota/packit

EXTRA_PROGRAMS = 	packit

sbin_PROGRAMS = 	@BINS@

common_SOURCES =        init.c \
                        define_defaults.c \
                        error.c \
                        injection.c \
                        capture.c \
                        shape_arp_hdr.c \
                        shape_tcp_hdr.c \
                        shape_udp_hdr.c \
                        shape_icmpv4_hdr.c \
                        shape_ipv4_hdr.c \
                        shape_ethernet_hdr.c \
                        shape_packet.c \
                        utils.c \
                        stats.c \
                        contrib/pcap_setnonblock.c

packit_SOURCES =        ${common_SOURCES} \
                        usage.c \
                        exit.c \
                        main.c \
                        print_ts.c \
                        print_arp_hdr.c \
                        print_tcp_hdr.c \
                        print_udp_hdr.c \
                        print_icmpv4_hdr.c \
                        print_ipv4_hdr.c \
                        print_ethernet_hdr.c \
                        print_pktdump.c \
                        print_capture.c \
                        print_injection.c

packit_LDFLAGS=

AM_CPPFLAGS = $(PACKIT_CPPFLAGS)
