%define version 0.6.0d
Name:		packit
Version:	%{version}
Release:	0
Source:		http://packit.sourceforge.net/packit-%{version}.tgz
URL:		http://packit.sourceforge.net/
License:	GPL
Group:		Networking/Utilities
BuildRoot:	/var/tmp/%{name}-rpmroot
Summary:	Network Injection And Capture Tool
Vendor:		Darren Bounds <dbounds@intrusense.com>
%description

Packit is a network auditing tool. It's value is derived from its
ability to customize, inject, monitor, and manipulate IP traffic.  By
allowing you to define (spoof) all TCP, UDP, ICMP, IP, ARP, RARP and
Ethernet header options, Packit can be useful in testing firewalls,
intrusion detection systems, port scanning, simulating network traffic
and general TCP/IP auditing.  Packit is also an excellent tool for
learning TCP/IP.

%prep
%setup

%build
CC='gcc -I/usr/include/pcap' ./configure --prefix=/usr
make

%install
mkdir -p $RPM_BUILD_ROOT/usr
make prefix=$RPM_BUILD_ROOT/usr install

%changelog
* Sat Jul 19 2003 William Stearns <wstearns@pobox.com>
  Updated to 0.6.0d sources.  Spec file updates, including listing out
  what files should be included as docs; the older spec file approach of
  just including [A-Z]* placed the _entire_ source tree, code, binaries,
  and everything, under /usr/share/doc/packit-%{version}/.  This trims a
  900K rpm down to 90K.  :-)
* Mon Jun 2 2003 Darren Bounds <dbounds@intrusense.com>
  0.6.0b-1: corrected a small issue on some platforms with pcap_setnonblock.c 
* Sat May 24 2003 Darren Bounds <dbounds@intrusense.com>
  0.6.0-1: updated for 0.6.0 release
* Wed Mar 12 2003 Bennett Todd <bet@rahul.net>
  0.5.0-1: initial wrap

%files
%defattr(-,root,root)
%attr(755,root,root)			/usr/sbin/packit
%attr(644,root,root)			/usr/man/man8/packit.8.gz
				%doc	ChangeLog INSTALL LICENSE VERSION docs/ICMP.txt
