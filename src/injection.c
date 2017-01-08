/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002 Darren Bounds <dbounds@intrusense.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 *
 * packit official page at https://github.com/eribertomota/packit
 */

#include "injection.h"

u_int16_t
inject_packet()
{
#ifdef DEBUG
    fprintf(stdout, "DEBUG: inject_packet()\n");
#endif

    if(libnet_write(pkt_d) == -1)
        return FAILURE;

    return SUCCESS;
}

void
injection_init()
{
    u_int16_t port_range = 0;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: injection_init()\n");
    fprintf(stdout, "DEBUG: cnt: %lld, interval_sec %d\n", cnt, interval_sec);
    fprintf(stdout, "DEBUG: p_mode: %d  burst_rate: %d\n", p_mode, burst_rate);
#endif

    signal(SIGTERM, injection_clean_exit);
    signal(SIGQUIT, injection_clean_exit);
    signal(SIGINT, injection_clean_exit);
    signal(SIGHUP, injection_clean_exit);

    if(hex_payload)
    {
        if((payload_len = format_hex_payload(payload)) == 0)
            fprintf(stdout, "Warning: Hex payload formatted incorrectly.\n");
    }
    else if(payload)
    {
	    payload_len = strlen((char*)payload);
#ifdef DEBUG
	    fprintf(stdout, "DEBUG: payload_len=%d\n", payload_len);
#endif
    }

    if(s_d_port != NULL)
    {
        if(strstr((char*)s_d_port, "-"))
        {
            cnt = parse_port_range(s_d_port);

            if(cnt < 1 || cnt > 65535)
                fatal_error("Invalid port range: %s", s_d_port);

            port_range = 1;
        }

        d_port = (u_int16_t)atoi((char*)s_d_port);
    }

    if(!device && (device = pcap_lookupdev(error_buf)) == NULL)
        fatal_error("Device lookup failure: Are you root?");

    if(strstr(device, "any")) strcpy(device, "lo");

    if(p_mode == M_TRACE)
        fprintf(stdout, "Mode:  Trace Route [Hop Max: %lu] using device: %s\n", cnt, device);
    else
        fprintf(stdout, "Mode:  Packet Injection using device: %s\n", device);

    if((pkt_d = libnet_init(init_type, device, error_buf)) == NULL)
        fatal_error("Unable to initialize packet injection");

    if(p_mode == M_INJECT)
        without_response(port_range);
    else
    if(p_mode == M_INJECT_RESPONSE || p_mode == M_TRACE)
        with_response(port_range);

#ifdef DEBUG
    fprintf(stdout, "DEBUG: Preparing to clean house and exit\n");
#endif
    injection_clean_exit(SUCCESS);

    return;
}

u_int16_t
with_response(u_int32_t port_range)
{
    char ufilter[1024];
    u_int32_t i, tr_retry = 0;
    u_int32_t dth_r, dstp = 0;
    u_int32_t localnet, netmask;
    u_int32_t d_link;

    struct bpf_program bpf;
    struct timespec n_sleep;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: with_response()\n");
#endif

    memset(&bpf, 0, sizeof(struct bpf_program));
    memset(&n_sleep, 0, sizeof(struct timespec));

    n_sleep.tv_nsec = 100;

    if(init_type == 0)
        link_layer = 1;

    if((pkt = pcap_open_live(device, 1500, 1, READ_TIMEOUT, error_buf)) == NULL)
        fatal_error("Unable to open device: %s", error_buf);

    if(pcap_lookupnet(device, &localnet, &netmask, error_buf) < 0)
        fprintf(stderr, "\nWarning: Unable to lookup network: %s\n", error_buf);

    if(cnt == 0) dstp = cnt = 1;

    for(i = 1; i < cnt + 1; i++)
    {
#ifdef DEBUG
        fprintf(stdout, "DEBUG: for() inj_cnt: %lld  cnt: %lld\n", inj_cnt, cnt);
#endif

        if(dstp) i = 0;

        pkt_d = shape_packet();

        switch(ip4hdr_o.p)
        {
             case IPPROTO_TCP:
                 snprintf(ufilter, 1024,
                     "dst host %s"
                     " && "
                     "(ip[9] = 6 && src host %s && src port 0x%x && dst port 0x%x)"
                     " || "
                     "(ip[9] = 1"
                     " && "
                     "(icmp[0] = 0xb || icmp[0] = 0x3)  && icmp[12:2] = 0x%04x)",
                     ip4hdr_o.s_addr, ip4hdr_o.d_addr, d_port, s_port, ip4hdr_o.id);

                 break;

             case IPPROTO_UDP:
                 snprintf(ufilter, 1024,
                     "dst host %s"
                     " && "
                     "(ip[9] = 17 && src host %s && src port 0x%x && dst port 0x%x)"
                     " || "
                     "(ip[9] = 1"
                     " && "
                     "(icmp[0] = 0xb || icmp[0] = 0x3)  && icmp[12:2] = 0x%04x)",
                     ip4hdr_o.s_addr, ip4hdr_o.d_addr, d_port, s_port, ip4hdr_o.id);

                 break;

             case IPPROTO_ICMP:
                 snprintf(ufilter, 1024,
                     "dst host %s && ip[9] = 1"
                     " && "
                     "((icmp[0] = 0x0 && icmp[4:2] = 0x%04x && icmp[6:2] = 0x%04x)"
                     " || "
                     "((icmp[0] = 0xe || icmp[0] = 0x12) && icmp[4:2] = 0x%04x && icmp[6:2] = 0x%04x)"
                     " || "
                     "((icmp[0] = 0xb || icmp[0] = 0x3)  && icmp[12:2] = 0x%04x))",
                     ip4hdr_o.s_addr, htons(i4hdr_o.id), htons(i4hdr_o.seqn),
                     i4hdr_o.id, i4hdr_o.seqn, ip4hdr_o.id);

                 break;
        }

        filter = ufilter;

#ifdef DEBUG
        fprintf(stdout, "DEBUG: filter: %s\n", filter);
#endif

        if(pcap_compile(pkt, &bpf, filter, 0, netmask) < 0)
            fprintf(stderr, "\nWarning: Unable to compile packet filters: %s\n", pcap_geterr(pkt));

        if(pcap_setfilter(pkt, &bpf) < 0)
            fatal_error("Unable to set packet filters: %s", pcap_geterr(pkt));

#ifdef HAVE_FREECODE
        pcap_freecode(&bpf);
#endif /* HAVE_FREECODE */

        if((d_link = pcap_datalink(pkt)) < 0)
            fatal_error("Unable to determine datalink type: %s", pcap_geterr(pkt));

#ifdef SYSV_DERIVED
#ifdef HAVE_SETNONBLOCK
#ifdef DEBUG
       fprintf(stdout, "DEBUG: pcap_setnonblock()\n");
#endif /* DEBUG */
        if(pcap_setnonblock(pkt, 1, error_buf) < 0)
            fatal_error("Unable to change to blocking mode: %s", error_buf);
#else /* HAVE_SETNONBLOCK */
        if(setnonblock(pkt, 1, error_buf) < 0)
            fatal_error("Unable to change to blocking mode: %s", error_buf);
#endif /* HAVE_SETNONBLOCK */
#endif /* SYSV_DERIVED */

        print_separator(1, 2, (p_mode == M_TRACE) ? "HOP %d" : "SND %d", inj_cnt);

start:
        if(!inject_packet())
            fatal_error("Unable to inject packet");

        gettimeofday(&bf_pcap, NULL);

        if(p_mode != M_TRACE)
        {
            print_ts(bf_pcap);
            print_injection_details();
        }

        hdr_len = retrieve_datalink_hdr_len(d_link);

#ifdef DEBUG
        fprintf(stdout, "DEBUG: start time: %ld.%ld\n",
            bf_pcap.tv_sec, bf_pcap.tv_usec);
        fprintf(stdout, "DEBUG: start dispatch loop\n");
#endif

        while(1)
        {
            dth_r = pcap_dispatch(pkt, 1, (pcap_handler)process_packets, NULL);

            if(dth_r < 0)
                fatal_error("Unable to inject packet");
            else
            if(dth_r > 0)
                break;

            gettimeofday(&af_pcap, NULL);

#ifdef DEBUG
            fprintf(stdout, "DEBUG: dispatch time: %ld.%ld\n",
                af_pcap.tv_sec, af_pcap.tv_usec);
#endif

            if(((af_pcap.tv_sec - bf_pcap.tv_sec) == r_timeout &&
                (bf_pcap.tv_usec < af_pcap.tv_usec)) ||
                (af_pcap.tv_sec - bf_pcap.tv_sec) > r_timeout)
            {

                if(p_mode == M_TRACE && tr_retry < 2)
                {
                    tr_retry++;
                    goto start;
                }
                else
                {
                    tr_retry = 0;
                    print_separator((p_mode == M_TRACE) ? 0 : 1, 1, "No Response From Peer");
                    break;
                }
            }

            nanosleep(&n_sleep, NULL);
        }

#ifdef DEBUG
        fprintf(stdout, "DEBUG: dispatch loop complete\n");
#endif

        libnet_clear_packet(pkt_d);

        if(p_mode == M_TRACE)
        {
            if(tr_fin == 1)
                return FAILURE;
            else
                ip4hdr_o.ttl++;
        }
        else
        if((ip4hdr_o.p == IPPROTO_TCP || ip4hdr_o.p == IPPROTO_UDP) && port_range)
            d_port++;
        else
        if(ip4hdr_o.p == IPPROTO_ICMP && i4hdr_o.type == ICMP_ECHO)
            i4hdr_o.seqn++;

        if(burst_rate != 0 && p_mode != M_TRACE && (inj_cnt % burst_rate) == 0 && i != cnt)
            sleep(interval_sec);

        inj_cnt++;
    }

    return FAILURE;
}

u_int16_t
without_response(u_int32_t port_range)
{
    u_int64_t i;
    u_int32_t dstp = 0;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: without_response()\n");
#endif

    gettimeofday(&bf_pcap, NULL);

    if(cnt == 0) dstp = cnt = 1;

    for(i = 1; i < cnt + 1; i++)
    {
        if(dstp) i = 0;

        pkt_d = shape_packet();

        if(!inject_packet())
            fatal_error("Unable to inject packet");

        if(verbose)
        {
            print_separator(1, 2, "SND %ld", inj_cnt);
            print_injection_details();

            if(burst_rate != 0 && (inj_cnt % burst_rate) == 0 && i != cnt)
                sleep(interval_sec);

        }
        else
        {
            if(inj_cnt == 1)
            {
                fprintf(stdout, "\n");
                print_injection_details();

                if(dstp)
                    fprintf(stderr, "\nWriting packet(s): ");
                else
                    fprintf(stderr, "\nWriting packet(s) (%lu): ", cnt);
            }

            if(burst_rate != 0 && (inj_cnt % burst_rate) == 0)
            {
                fprintf(stderr, ".");

                if(i != cnt)
                    sleep(interval_sec);
            }
        }

        gettimeofday(&af_pcap, NULL);

        libnet_clear_packet(pkt_d);

        if(ip4hdr_o.p == IPPROTO_ICMP &&
            i4hdr_o.type == ICMP_ECHO)
        {
            i4hdr_o.seqn++;
        }

        if((ip4hdr_o.p == IPPROTO_TCP ||
            ip4hdr_o.p == IPPROTO_UDP) && port_range)
        {
            d_port++;
        }

        inj_cnt++;
    }

    return SUCCESS;
}

