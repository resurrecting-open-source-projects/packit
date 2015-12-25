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


sbin_PROGRAMS = 	packit 

packit_SOURCES =        usage.c \
                        main.c \
                        injection.c \
                        capture.c \
                        shape_arp_hdr.c \
                        shape_tcp_hdr.c \
                        shape_udp_hdr.c \
                        shape_icmpv4_hdr.c \
                        shape_ipv4_hdr.c \
                        shape_ethernet_hdr.c \
                        shape_packet.c \
                        print_timestamp.c \
                        print_arp_hdr.c \
                        print_tcp_hdr.c \
                        print_udp_hdr.c \
                        print_icmpv4_hdr.c \
                        print_ipv4_hdr.c \
                        print_ethernet_hdr.c \
                        print_pktdump.c \
                        print_injection.c \
                        utils.c \
                        stats.c \
                        exit.c \
                        error.c \
                        contrib/pcap_setnonblock.c

INCLUDES=@INCLUDES@

all:
	cp packit $(top_srcdir)
	strip $(top_srcdir)/packit

clean:
	rm -f $(top_srcdir)/packit

distclean:
	rm -f $(top_srcdir)/packit


