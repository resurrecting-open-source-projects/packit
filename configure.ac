# Packit -- network injection and capture tool
#
# Original author: Darren Bounds <dbounds@intrusense.com>
#
# Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
# Copyright 2007      LaMont Jones <lamont@debian.org>
# Copyright 2013      Mats Erik Andersson <gnu@gisladisker.se>
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

AC_PREREQ([2.69])
AC_INIT([packit], [1.6], [https://github.com/eribertomota/packit/issues])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS(config.h)
AC_MSG_RESULT(beginning auto-configuration process for packit...)
AC_PREFIX_DEFAULT(/usr/local)
AM_INIT_AUTOMAKE([subdir-objects])

AC_PROG_CC
AC_MSG_CHECKING(for gcc)
if test "$GCC" = yes; then
    CFLAGS="${CFLAGS} -Wall"
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi

DEBUG="no"
BINS="packit"

AC_ARG_ENABLE(debug,
    [ --enable-debug          Enable debugging],
    [ if test "$GCC" = yes; then
          DEBUG="yes"
          CFLAGS="${CFLAGS} -DDEBUG -ggdb"
      else
          DEBUG="yes"
          CFLAGS="${CFLAGS} -DDEBUG"
      fi
    ],)

AC_ARG_WITH(capture,
    [ --without-capture       Remove packet capture support],
    with_capture=$withval, with_capture=yes)
if test "x$with_capture" = "xyes" ; then
    with_capture="yes"
    AC_DEFINE(WITH_CAPTURE, 1, Enable Capture)
else
    with_capture="no"
fi

AC_ARG_WITH(injection,
    [  --without-injection     Remove packet injection support],
    with_injection=$withval,with_injection=yes)
if test "x$with_injection" = "xyes"; then
    with_injection="yes"
    AC_DEFINE(WITH_INJECTION, 1, Enable Injection)
else
    with_injection="no"
fi

AC_SUBST(BINS)
AC_CANONICAL_HOST

SHELL="/bin/sh"

PACKIT_CPPFLAGS='-I$(top_srcdir) -I$(top_srcdir)/includes'

dnl Checks for OS type.
case "$host" in
    *-freebsd*)
        AC_DEFINE(BSD_DERIVED, 1, OS BSD Derived)
        AC_DEFINE(FREEBSD, 1, FreeBSD)
        ;;
    *-netbsd*)
        AC_DEFINE(BSD_DERIVED, 1, OS BSD Derived)
        AC_DEFINE(NETBSD, 1, NetBSD)
        ;;
    *-openbsd*)
        AC_DEFINE(BSD_DERIVED, 1, OS BSD Derived)
        AC_DEFINE(FREEBSD, 1, OpenBSD)
        ;;
    *-apple*)
        AC_DEFINE(BSD_DERIVED, 1, OS BSD Derived)
        AC_DEFINE(MACOS, 1, MacOS)
        LDFLAGS="${LDFLAGS} -L/sw/lib"
        PACKIT_CPPFLAGS="${PACKIT_CPPFLAGS} -I/sw/include";
        ;;
    *-linux*)
        AC_DEFINE(SYSV_DERIVED, 1, OS SysV Derived)
        AC_DEFINE(LINUX, 1, Linux)
        PACKIT_CPPFLAGS="${PACKIT_CPPFLAGS} -I/usr/include/pcap";
        ;;
    *-solaris*)
        AC_DEFINE(SYSV_DERIVED, 1, OS SysV Derived)
        AC_DEFINE(SOLARIS, 1, Solaris)
        ;;
    *-aix*)
        AC_DEFINE(SYSV_DERIVED, 1, OS SysV Derived)
        AC_DEFINE(AIX, 1, AIX)
        ;;
    *-hpux*)
        AC_DEFINE(SYSV_DERIVED, 1, OS SysV Derived)
        AC_DEFINE(HPUX, 1, HPUX)
        ;;
esac

AC_SUBST(PACKIT_CPPFLAGS)

dnl Checks for typedef
AC_CHECK_TYPE(u_int8_t, unsigned char)
AC_CHECK_TYPE(u_int16_t, unsigned short)
AC_CHECK_TYPE(u_int32_t, unsigned int)
AC_CHECK_TYPE(u_int64_t, unsigned long long)

dnl Checks for header files.
AC_CHECK_HEADERS(signal.h pcap-bpf.h sys/time.h)

AC_ARG_WITH(libnet_includes,
    [  --with-libnet-includes=DIR    libnet include directory],
    [with_libnet_includes="$withval"],[with_libnet_includes=no])

if test "$with_libnet_includes" != "no"; then
    CFLAGS="${CFLAGS} -I${with_libnet_includes}"
fi

AC_CHECK_HEADERS(libnet.h,, LIBNET="no")
if test "$LIBNET" = "no"; then
    echo ""
    echo "Error: Can't find libnet 1.1.0 or greater. Visit https://github.com/sam-github/libnet for the latest version."
    exit;
fi

AC_ARG_WITH(libpcap_includes,
     [  --with-libpcap-includes=DIR   libcap include directory],
     [with_libpcap_includes="$withval"],[with_libpcap_includes=no])

if test "$with_libpcap_includes" != "no"; then
    CFLAGS="${CFLAGS} -I${with_libpcap_includes}"
fi

AC_CHECK_HEADERS(pcap.h,, LIBPCAP="no")
if test "$LIBNET" = "no"; then
    echo ""
    echo "Error: Can't find Libpcap. Visit https://github.com/the-tcpdump-group/libpcap for the latest version."
    exit;
fi

dnl Checks for library functions.
AC_CHECK_FUNCS(printf fprintf snprintf sprintf strdup strrchr strstr strncasecmp \
    strtol strncmp strncat memset malloc gethostbyname gettimeofday getuid \
    select setitimer)

AC_ARG_WITH(libnet_libraries,
    [  --with-libnet-libraries=DIR   libnet library directory],
    [with_libnet_libraries="$withval"],[with_libnet_libraries=no])

if test "$with_libnet_libraries" != "no"; then
    LDFLAGS="${LDFLAGS} -L${with_libnet_libraries}"
fi

AC_CHECK_LIB(net, libnet_build_ipv4,, LIBNET="no")
if test "$LIBNET" = "no"; then
    echo ""
    echo "Error: Can't find libnet 1.1.0 or greater. Visit https://github.com/sam-github/libnet for the latest version."
    exit;
fi

AC_ARG_WITH(libpcap_libraries,
    [  --with-libpcap-libraries=DIR  libcap library directory],
    [with_libpcap_libraries="$withval"],[with_libpcap_libraries=no])

if test "$with_libpcap_libraries" != "no"; then
    LDFLAGS="${LDFLAGS} -L${with_libpcap_libraries}"
fi

AC_CHECK_LIB(pcap, pcap_open_live,, LIBPCAP="no")
if test "$LIBPCAP" = "no"; then
    echo ""
    echo "Error: Can't find Libpcap. Visit https://github.com/the-tcpdump-group/libpcap for the latest version."
    exit;
else
    AC_CHECK_LIB(pcap, pcap_setnonblock,, SETNONBLOCK="no")
    if test "$SETNONBLOCK" = "no"; then
        echo "compensating for lack of pcap_setnonblock()"
    else
        AC_DEFINE(HAVE_SETNONBLOCK, 1 , SETNONBLOCK)
    fi

    AC_CHECK_LIB(pcap, pcap_freecode,, FREECODE="no")
    if test "$FREECODE" = "no"; then
        echo "compensating for lack of pcap_freecode()"
    else
        AC_DEFINE(HAVE_FREECODE, 1, FREECODE)
    fi
fi

AC_MSG_CHECKING(for bpf)
if test -r /dev/bpf0; then
    AC_DEFINE(HAVE_BPF, 1, BPF)
    AC_MSG_RESULT(yes)
elif test -c /dev/bpf0; then
    AC_DEFINE(HAVE_BPF, 1, BPF)
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi

AC_PROG_INSTALL
AC_CONFIG_FILES([Makefile src/Makefile man/Makefile src/version.h])
AC_OUTPUT

BINDIR=`eval echo ${bindir}`; BINDIR=`eval echo ${BINDIR}`;
MANDIR=`eval echo ${mandir}/${mansubdir}`; MANDIR=`eval echo ${MANDIR}`;

echo ""
echo "                  _    _ _"
echo " _ __   __ _  ___| | _(_) |_"
echo "| '_ \ / _\` |/ __| |/ / | __|"
echo "| |_) | (_| | (__|   <| | |_"
echo "| .__/ \__,_|\___|_|\_\_|\__|"
echo "|_|"
echo ""
echo "has been configured with the following options:"
echo "-----------------------------------------------"
echo "Host type             : ${host}"
echo "Compiler              : ${CC}"
echo "Compiler flags        : ${CFLAGS}"
echo "Linker flags          : ${LDFLAGS}"
echo "Libraries             : ${LIBS}"
echo ""
echo "Binary                : ${BINDIR}"
echo "Manual pages          : ${MANDIR}"
echo ""
echo "Injection support     : ${with_injection}"
echo "Capture support       : ${with_capture}"
echo "Enable debugging      : ${DEBUG}"
echo "-----------------------------------------------"
echo ""

dnl EOF
