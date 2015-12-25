#
# author: Darren Bounds <dbounds@intrusense.com>
# copyright: Copyright (C) 2002 by Darren Bounds
# license: This software is under GPL version 2 of license
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# packit official page at http://packit.sourceforge.net
#


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

INCLUDES=@INCLUDES@

all:
	strip @BINS@
	cp @BINS@ $(top_srcdir)

clean:
	rm -f $(top_srcdir)/packit

distclean:
	rm -f $(top_srcdir)/packit

