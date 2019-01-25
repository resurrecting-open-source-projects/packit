/*
 * Packit -- network injection and capture tool
 *
 * Original author: Darren Bounds <dbounds@intrusense.com>
 *
 * Copyright 2002-2004 Darren Bounds <dbounds@intrusense.com>
 * Copyright 2015      Gentoo Linux
 * Copyright 2016-2017 Robert Krause <ruport@f00l.de>
 * Copyright 2017      Sharad B
 * Copyright 2019      Sander Kleijwegt <sander.kleijwegt@netscout.com>
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

#include "utils.h"

u_int32_t
retrieve_rand_int(u_int32_t r_size)
{
    static u_int32_t r_int;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: retrieve_rand_int()\n");
#endif

    r_int++;

    srand(time(0) ^ getpid() * r_int);
    r_int = rand() % r_size;

    return r_int;
}

u_int16_t
retrieve_datalink_hdr_len(u_int32_t d_link)
{
    u_int16_t len = 0;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: retrieve_datalink_hdr_len()\n");
#endif

    switch(d_link)
    {
        case DLT_NULL:
            len = 4;
            break;

        case DLT_EN10MB:
            len = ETH_H;
            break;

        default:
            len = ETH_H;
            break;
    }

#ifdef DEBUG
    fprintf(stdout, "DEBUG: g_hdr_len: %d\n", len);
#endif

    return len;
}

u_int8_t *retrieve_rand_ipv4_addr(u_int8_t *ip)
{
    u_int8_t oct, oct_cnt;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: retrive_rand_ipv4_addr()\n");
#endif

    for(oct_cnt = 1; oct_cnt < 5; oct_cnt++)
    {

        while(1)
        {
            oct = (u_int8_t)retrieve_rand_int(0xFF);

            if(oct_cnt != 1 ||
              (oct_cnt == 1 && oct > 0 && oct < 239))
                break;
        }

        if(oct_cnt != 1)
            sprintf((char*)ip, "%s.%d", ip, oct);
        else
            sprintf((char*)ip, "%d", oct);
    }

    return ip;
}

u_int8_t *retrieve_rand_ethernet_addr(u_int8_t *eaddr)
{
    u_int16_t oct, oct_cnt;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: retrieve_rand_ethernet_addr()\n");
#endif

   for(oct_cnt = 1; oct_cnt < 7; oct_cnt++)
   {
        oct = (u_int8_t)retrieve_rand_int(0xFF);

       if(oct_cnt != 1)
           sprintf((char*)eaddr, "%s:%0x", eaddr, oct);
       else
           sprintf((char*)eaddr, "%0x", oct);
   }

    return eaddr;
}

void
print_separator(int bnl, int anl, char *msgp, ...)
{
    u_int16_t i;
    u_int16_t max_len = 76;
    u_int16_t msg_len = 0;
    char msg[255];

    va_list va;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: print_separator()\n");
#endif

    va_start(va, msgp);
    vsnprintf(msg, 255, msgp, va);

    msg_len = strlen(msg);

    for(i = 0; i < bnl; i++)
        fprintf(stdout, "\n");

    fprintf(stdout, "-| %s |-", msg);

    for(i = 0; i < (max_len - msg_len - 6); i++)
        fprintf(stdout, "-");

    for(i = 0; i < anl; i++)
        fprintf(stdout, "\n");

    return;
}

char *retrieve_icmp_code(u_int16_t type, u_int16_t code) {
    char *icmp_c;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: retrieve_icmp_code()\n");
#endif

    icmp_c = malloc(sizeof(char) * 32);

    if(type == ICMP_UNREACH)
    {
        switch(code)
        {
            case ICMP_UNREACH_NET:
                sprintf(icmp_c, "Network");
                break;

            case ICMP_UNREACH_HOST:
                sprintf(icmp_c, "Host");
                break;

            case ICMP_UNREACH_PROTOCOL:
                sprintf(icmp_c, "Protocol");
                break;

            case ICMP_UNREACH_PORT:
                sprintf(icmp_c, "Port");
                break;

            case ICMP_UNREACH_NEEDFRAG:
                sprintf(icmp_c, "Need Fragment");
                break;

            case ICMP_UNREACH_SRCFAIL:
                sprintf(icmp_c, "Source Fail");
                break;

            case ICMP_UNREACH_NET_UNKNOWN:
                sprintf(icmp_c, "Network Unknown");
                break;

            case ICMP_UNREACH_HOST_UNKNOWN:
                sprintf(icmp_c, "Host Unknown");
                break;

            case ICMP_UNREACH_ISOLATED:
                sprintf(icmp_c, "Isolated");
                break;

            case ICMP_UNREACH_NET_PROHIB:
                sprintf(icmp_c, "Network Prohibited");
                break;

            case ICMP_UNREACH_HOST_PROHIB:
                sprintf(icmp_c, "Host Prohibited");
                break;

            case ICMP_UNREACH_TOSNET:
                sprintf(icmp_c, "ToS Network");
                break;

            case ICMP_UNREACH_TOSHOST:
                sprintf(icmp_c, "ToS Host");
                break;

            case ICMP_UNREACH_FILTER_PROHIB:
                sprintf(icmp_c, "Filter Prohibited");
                break;

            case ICMP_UNREACH_HOST_PRECEDENCE:
                sprintf(icmp_c, "Host Precedence");
                break;

            case ICMP_UNREACH_PRECEDENCE_CUTOFF:
                sprintf(icmp_c, "Precedence Cutoff");
                break;

            default:
                sprintf(icmp_c, "Unknown");
                break;
        }
    }
    else
    if(type == ICMP_REDIRECT)
    {
        switch(code)
        {
            case ICMP_REDIRECT_NET:
                sprintf(icmp_c, "Network");
                break;

            case ICMP_REDIRECT_HOST:
                sprintf(icmp_c, "Host");
                break;

            case ICMP_REDIRECT_TOSNET:
                sprintf(icmp_c, "ToS Net");
                break;

            case ICMP_REDIRECT_TOSHOST:
                sprintf(icmp_c, "ToS Host");
                break;

            default:
                sprintf(icmp_c, "Unknown");
                break;
        }
    }
    else
    if(type == ICMP_TIMXCEED)
    {
        switch(code)
        {
            case ICMP_TIMXCEED_INTRANS:
                sprintf(icmp_c, "In Transit");
                break;

            case ICMP_TIMXCEED_REASS:
                sprintf(icmp_c, "Reassembly");
                break;

            default:
                sprintf(icmp_c, "Unknown");
                break;
        }
    }
    else
    if(type == ICMP_PARAMPROB)
    {
        switch(code)
        {
            case ICMP_PARAMPROB_OPTABSENT:
                sprintf(icmp_c, "Missing Option");
                break;

            default:
                sprintf(icmp_c, "Unknown");
                break;
        }
    }
    else
    {
        sprintf(icmp_c, "Unknown");
    }

    return icmp_c;
}

char *retrieve_icmp_type(u_int16_t type) {
    char *icmp_t;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: retrieve_icmp_type()\n");
#endif

    icmp_t = malloc(sizeof(char) * 32);
    memset(icmp_t, 0, sizeof(char) * 32);

    switch(type)
    {
        case ICMP_ECHOREPLY:
            sprintf(icmp_t, "Echo Reply");
            break;

        case ICMP_UNREACH:
            sprintf(icmp_t, "Unreachable");
            break;

        case ICMP_SOURCEQUENCH:
            sprintf(icmp_t, "Source Quench");
            break;

        case ICMP_REDIRECT:
            sprintf(icmp_t, "Redirect");
            break;

        case ICMP_ECHO:
            sprintf(icmp_t, "Echo Request");
            break;

        case ICMP_TIMXCEED:
            sprintf(icmp_t, "Time Exceeded");
            break;

        case ICMP_PARAMPROB:
            sprintf(icmp_t, "Param Problem");
            break;

        case ICMP_TSTAMP:
            sprintf(icmp_t, "Timestamp");
            break;

        case ICMP_TSTAMPREPLY:
            sprintf(icmp_t, "Timestamp Reply");
            break;

        case ICMP_IREQ:
            sprintf(icmp_t, "Info Request");
            break;

        case ICMP_IREQREPLY:
            sprintf(icmp_t, "Info Reply");
            break;

        case ICMP_ROUTERADVERT:
            sprintf(icmp_t, "Router Advertise");
            break;

        case ICMP_ROUTERSOLICIT:
            sprintf(icmp_t, "Router Selection");
            break;

        case ICMP_MASKREQ:
            sprintf(icmp_t, "Address Mask Request");
            break;

        case ICMP_MASKREPLY:
            sprintf(icmp_t, "Address Mask Reply");
            break;

        case ICMP_TRACEROUTE:
            sprintf(icmp_t, "Traceroute");
            break;

        default:
            sprintf(icmp_t, "Unknown");
            break;
    }

    return icmp_t;
}

char *retrieve_arp_type(u_int16_t op_type) {
    char *arp_t;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: retrieve_arp_type() OPTYPE: %d\n", op_type);
#endif

    arp_t = malloc(sizeof(char) * 32);

    switch(op_type)
    {
        case ARPOP_REQUEST:
            sprintf(arp_t, "Request");
            break;

        case ARPOP_REPLY:
            sprintf(arp_t, "Reply");
            break;

        case ARPOP_REVREQUEST:
            sprintf(arp_t, "Reverse Request");
            break;

        case ARPOP_REVREPLY:
            sprintf(arp_t, "Reverse Reply");
            break;

        case ARPOP_INVREQUEST:
            sprintf(arp_t, "Inverse Request");
            break;

        case ARPOP_INVREPLY:
            sprintf(arp_t, "Inverse Reply");
            break;

        default:
            sprintf(arp_t, "Unknown");
            break;
    }

#ifdef DEBUG
    fprintf(stdout, "DEBUG: ARP type: %s\n", arp_t);
#endif

    return arp_t;
}

char *retrieve_arp_hw_type(u_int16_t hw_type) {
    char *hw_t;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: retrieve_arp_hw_type() HWTYPE: %d\n", hw_type);
#endif

    hw_t = malloc(sizeof(char) * 32);

    switch(hw_type)
    {
        case ARPHRD_NETROM:
            sprintf(hw_t, "Net/ROM Pseudo");
            break;

        case ARPHRD_ETHER:
            sprintf(hw_t, "Ethernet 10/100");
            break;

        case ARPHRD_EETHER:
            sprintf(hw_t, "Experimental Ethernet");
            break;

        case ARPHRD_AX25:
            sprintf(hw_t, "AX.25 Level 2");
            break;

        case ARPHRD_PRONET:
            sprintf(hw_t, "ProNet Token Ring");
            break;

        case ARPHRD_IEEE802:
            sprintf(hw_t, "IEEE 802.2 Ethernet");
            break;

        case ARPHRD_ARCNET:
            sprintf(hw_t, "ARCNet");
            break;

        case ARPHRD_APPLETLK:
            sprintf(hw_t, "AppleTalk");
            break;

        case ARPHRD_LANSTAR:
            sprintf(hw_t, "Lanstar");
            break;

        case ARPHRD_DLCI:
            sprintf(hw_t, "Frame Relay DLCI");
            break;

        case ARPHRD_ATM:
            sprintf(hw_t, "ATM");
            break;

        case ARPHRD_METRICOM:
            sprintf(hw_t, "Metricom STRIP");
            break;

        case ARPHRD_IPSEC:
            sprintf(hw_t, "IPsec Tunnel");
            break;
    }

#ifdef DEBUG
    fprintf(stdout, "DEBUG: ARP hardware type: : %s\n", hw_t);
#endif

    return hw_t;
}

int
retrieve_tcp_flags()
{
    int flags = 0;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: retrieve_tcp_flags()\n");
#endif

    if(g_thdr_o.urg)
        flags |= TH_URG;

    if(g_thdr_o.ack)
        flags |= TH_ACK;

    if(g_thdr_o.psh)
        flags |= TH_PUSH;

    if(g_thdr_o.rst)
        flags |= TH_RST;

    if(g_thdr_o.syn)
        flags |= TH_SYN;

    if(g_thdr_o.fin)
        flags |= TH_FIN;

    return flags;
}

u_int8_t format_ethernet_addr(u_int8_t *ethstr, u_int8_t u_eaddr[6]) {
    int i = 0;
    long base16;
    char *eptr, *delim = ":";
    u_int8_t o_ethstr[18] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

#ifdef DEBUG
    fprintf(stdout, "DEBUG: format_ethernet_addr()\n");
#endif

    if(ethstr)
        strncpy((char*)o_ethstr, (char*)ethstr, 18);
    else
    {
        u_eaddr = o_ethstr;
        return 1;
    }

    for(eptr = strtok((char*)o_ethstr, delim);
         eptr;
         eptr = strtok(NULL, delim))
    {
        if((base16 = strtol(eptr, 0, 16)) > 0xff)
            return 0;

        u_eaddr[i] = base16;
        i++;
    }

    if(i != 6)
        return 0;

    ethstr = o_ethstr;

    return 1;
}

u_int16_t parse_port_range(char *rangestr) {
    char o_rangestr[11], *ptr, *delim = "-";
    u_int16_t i, range = 0;
    int spread[10];

#ifdef DEBUG
    fprintf(stdout, "DEBUG: parse_port_range(): %s\n", rangestr);
#endif

    if(rangestr)
        strncpy(o_rangestr, rangestr, 11);

    for(i = 0, ptr = strtok(o_rangestr, delim);
        ptr;
        ptr = strtok(NULL, delim))
    {
        spread[i] = (int)atoi(ptr);

        if(spread[i] < 1 || spread[i] > 65535)
            return -1;

        i++;
    }

    rangestr = o_rangestr;
    range = spread[1] - spread[0] + 1;
    g_d_port = (u_int16_t)spread[0];

    if(range < 1 || i != 2)
        return -1;

    return range;
}

/**
 * Creates fake payload of size
 *   (packet length) - (current header length)
 *
 * The payload consists of u_int8_t values from from 48 .. 126
 * followed by 33 .. 126 as many times as needed.
 *
 * @param clen - Header length (already being used in the packet)
 * @param dlen - Packet length
 * @return malloc'ed u_int8_t array with the new payload
 */
unsigned char *generate_padding(u_int16_t clen, u_int16_t dlen)
{
    u_int8_t c = 48;
    unsigned char *string;
    u_int16_t i;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: generate_padding()\n");
#endif

    if(dlen < clen)
    {
        fprintf(stdout, "Error: Requested packet size less than total header length\n");
        return NULL;
    }

    string = malloc(sizeof(u_int8_t *) * (dlen - clen + 1));

    for(i = 0; clen < dlen; ++i, ++clen)
    {
        if(c > 126)
            c = 33;
        string[i] = c++;
    }
    string[i] = 0;

    return string;
}

u_int32_t format_hex_payload(char *string)
{
    char *pl;
    char *i, *delim = " ";
    char tchar[2];
    long c;
    u_int32_t len = 0;

#ifdef DEBUG
    fprintf(stdout, "DEBUG: format_hex_payload()\n");
#endif

    pl = strdup(string);
    pl[0] = pl[1] = 20;

    memset(string, 0, strlen(string));
    memset(tchar, 0, 2);

    /*
     * skip the first 3 chars because we know they are spaces
     */
    for(i = strtok(pl+3, delim); i; i = strtok(NULL, delim)) {
        if((c = strtol(i, 0, 16)) > 0xff)
            return 0;

        sprintf(tchar,"%c",(u_int8_t)c);
        strncpy(string+len,tchar,2);
        len++;
    }

    return len;
}
