# Packit -- network injection and capture tool
#
# Original author: Darren Bounds <dbounds@intrusense.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright 2002 Darren Bounds <dbounds@intrusense.com>
# Copyright 2016 Joao Eriberto Mota Filho <eriberto@eriberto.pro.br>
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
# packit official page at https://github.com/resurrecting-open-source-projects/packit

AUTOMAKE_OPTIONS = foreign no-dependencies

SUBDIRS = src

man_MANS = man/packit.8

distclean-local:
	rm -rf autom4te.cache
	rm -f aclocal.m4 compile config.* configure depcomp install-sh \
              Makefile.in missing man/Makefile.in src/Makefile.in
