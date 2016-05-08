# author: Darren Bounds <dbounds@intrusense.com>
# Copyright 2002 Darren Bounds
# Copyright 2016 Joao Eriberto Mota Filho
#
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

include $(top_srcdir)/Makefile.am.common

SUBDIRS = src man

EXTRA_DIST = Makefile.am.common

clean:
	-rm -f packit \
	stamp-h1 \
	src/*.o \
	src/packit \
	src/version.h

clean-local: clean
	-rm -rf autom4te.cache \
	src/.deps

	-rm -f aclocal.m4 \
	compile \
	config.* \
	configure \
	depcomp \
	install-sh \
	Makefile.in \
	missing \
	man/Makefile.in \
	src/Makefile \
	src/Makefile.in
