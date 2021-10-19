// SPDX-License-Identifier: BSD-4-Clause

/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997, 1998
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the Computer Systems
 *      Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "pcap-int.h"

#include <errno.h>
#include <fcntl.h>

#define PCAP_ERRBUF_MAX 	256

int
setnonblock(pcap_t *pt, int nonblock, char *errbuf)
{
        int fdflags;

        fdflags = fcntl(pt->fd, F_GETFL, 0);
        if (fdflags == -1) {
                snprintf(pt->errbuf, PCAP_ERRBUF_SIZE, "F_GETFL: %s",
                    pcap_strerror(errno));
                return (-1);
        }
        if (nonblock)
                fdflags |= O_NONBLOCK;
        else
                fdflags &= ~O_NONBLOCK;
        if (fcntl(pt->fd, F_SETFL, fdflags) == -1) {
                snprintf(pt->errbuf, PCAP_ERRBUF_SIZE, "F_SETFL: %s",
                    pcap_strerror(errno));
                return (-1);
        }
        return (0);
}

