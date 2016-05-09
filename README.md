# PACKIT
**Network injection and capture tool**


<br><br>
**1. HELP THIS PROJECT**<br>
**2. WHAT IS PACKIT?**<br>
**3. BUILDING FROM SOURCE**<br>



--------------------
1. HELP THIS PROJECT
--------------------

Packit needs your help. **If you are a programmer** and if you wants to
help a nice project, this is your opportunity.

My name is Eriberto and **I am not a C developer**. I imported Packit from
its old repository[1] to GitHub (the original homepage and developer are
inactive). After this, I applied all patches found in Debian project and
other places for this program. All my work was registered in ChangeLog
file (version 1.1 and later releases). I also maintain Packit packaged in
Debian[2].

If you are interested to help Packit, read the [CONTRIBUTING.md](CONTRIBUTING.md) file.

[1] http://packetfactory.openwall.net/projects/packit<br>
[2] https://packages.qa.debian.org/p/packit.html<br>


------------------
2. WHAT IS PACKIT?
------------------

Packit (PACket toolKIT) is a network auditing tool. It uses libpcap
and can make real packages (frames) that are able to travel in a
network. Packit also allows one to add personalized payloads. Other
good feature is the possibility to read dump files created by
tcpdump.

Packit has an ability to customize, inject, monitor and manipulate IP
traffic. By allowing you to define (spoof) nearly all TCP, UDP, ICMP,
IP, ARP, RARP, and Ethernet header options, Packit can be useful for
the following scenarios:

  * tests in firewalls; <br>
  * tests in Intrusion Detection Systems (IDS); <br>
  * tests in Intrusion Prevention Systems (IPS); <br>
  * tests in proxies; <br>
  * tests in port scanning detectors; <br>
  * network traffic simulations; <br>
  * security tests; and <br>
  * general TCP/IP auditing and pentests. <br>

Packit is also an excellent tool for learning TCP/IP. However, this
program does not support IPv6.


-----------------------
3. BUILDING FROM SOURCE
-----------------------

Packit requires the following elements to compile:

  * autoconf >= 2.69 <br>
  * libnet >= 1.1.2 <br>
  * libpcap >= 0.8 <br>

Packit source installation is simple:

    $ ./autogen.sh
    $ ./configure
    $ make

Then as 'root':

    # make install
