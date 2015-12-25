Name: packit
Version: 0.6.0c
Release: 1
Source: http://packit.sourceforge.net/downloads/packit-0.6.0c.tgz
URL: http://packit.sourceforge.net/
License: GPL
Group: Networking/Utilities
BuildRoot: /var/tmp/%{name}-rpmroot
Summary: Network Injection And Capture Tool
%description

Packit is a network auditing tool. It's value is derived from its ability to 
customize, inject, monitor, and manipulate IP traffic. By allowing you
to define (spoof) all TCP, UDP, ICMP, IP, ARP, RARP and Ethernet
header options, Packit can be useful in testing firewalls, intrusion
detection systems, port scanning, simulating network traffic and general
TCP/IP auditing. Packit is also an excellent tool for learning TCP/IP.

%prep
%setup

%build
CC='gcc -I/usr/include/pcap' ./configure --prefix=/usr
make

%install
mkdir -p $RPM_BUILD_ROOT/usr
make prefix=$RPM_BUILD_ROOT/usr install

%changelog
* Tue Jun 3 2003 Darren Bounds <dbounds@intrusense.com>
  0.6.0c-1: corrected a problem with the fix in 0.6.0c and added some additional configure tests
* Mon Jun 2 2003 Darren Bounds <dbounds@intrusense.com>
  0.6.0b-1: corrected a small issue on some platforms with pcap_setnonblock.c 
* Sat May 24 2003 Darren Bounds <dbounds@intrusense.com>
  0.6.0-1: updated for 0.6.0 release
* Wed Mar 12 2003 Bennett Todd <bet@rahul.net>
  0.5.0-1: initial wrap

%files
%defattr(-,root,root)
/usr/sbin/*
%doc /usr/man/*/*
%doc [A-Z]* docs
