Name: packit
Version: 0.6.0b
Release: 1
Source: http://packit.sourceforge.net/packit-0.6.0b.tgz
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
