/*
 * Copyright (c) 2001,2002 Sebastien Petit <spe@bsdfr.org>
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution. Obviously, it
 *    would be nice if you gave credit where credit is due but requiring it
 *    would be too onerous.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastien Petit.
 * 4. Neither the name of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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
 *
 * $Id: vrrp_network.c,v 1.27 2004/04/04 19:45:46 rival Exp $
 */

#include <errno.h>
#include <sys/param.h>
#include "vrrp_network.h"
#include "vrrp_ah.h"

u_short         ip_id;

/* Initialisation pour l'identification IP */
void 
vrrp_network_initialize(void)
{
	srand(time(NULL));
	ip_id = random() % 65535;

	return;
}

/* Open VRRP socket for reading */
char 
vrrp_network_open_socket(struct vrrp_vr * vr)
{
	struct timeval timeout;
	int hincl = 1;

	vr->sd = socket(AF_INET, SOCK_RAW, IPPROTO_VRRP);
	if (vr->sd == -1) {
		syslog(LOG_ERR, "cannot open raw socket for VRRP protocol [ AF_INET, SOCK_RAW, IPPROTO_VRRP ]: %s", strerror(errno));
		return -1;
	}
	if (setsockopt(vr->sd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl))) {
		syslog(LOG_ERR, "cannot set IP_HDRINCL option on the IPPROTO_IP raw socket: %s", strerror(errno));
		return -1;
	}
	timeout.tv_sec  = 0;
	timeout.tv_usec = 100000;
	if (setsockopt(vr->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
		syslog(LOG_ERR, "cannot set SO_RCVTIMEO option on the IPPROTO_VRRP raw socket: %s", strerror(errno));
		return -1;
	}

	return 0;
}

ssize_t
vrrp_network_send_packet(char *buffer, int sizebuf, int sd, int log)
{
	struct sockaddr_in addr;
	ssize_t          octets;

	addr.sin_family = AF_INET;
	addr.sin_port = 0;
	addr.sin_len = sizeof(struct sockaddr_in);
	addr.sin_addr.s_addr = inet_addr(VRRP_MULTICAST_IP);
	octets = sendto(sd, buffer, sizebuf, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if (octets < 0) {
		if (log)
			syslog(LOG_ERR, "can't write to socket: %s", strerror(errno));
		return -1;
	}

	return octets;
}

u_int 
vrrp_network_vrrphdr_len(struct vrrp_vr * vr)
{
	u_int           len = sizeof(struct vrrp_hdr);

	len += (vr->cnt_ip << 2) + VRRP_AUTH_DATA_LEN;

	return len;
}

void 	 
vrrp_network_init_iphdr(char *buffer, struct vrrp_vr * vr) 	 
{ 	 
	 struct ip      *iph = (struct ip *)buffer; 	 
  	 
	 iph->ip_hl = 5;
	 iph->ip_v = 4;
	 iph->ip_tos = 0;
#if (defined(__FreeBSD__) && (__FreeBSD_version < 1100030)) || defined(__NetBSD__)
	 iph->ip_len = sizeof(struct ip) + vrrp_network_vrrphdr_len(vr) + vrrp_ah_ahhdr_len(vr);
#else
	 iph->ip_len = htons(sizeof(struct ip) + vrrp_network_vrrphdr_len(vr) + vrrp_ah_ahhdr_len(vr));
#endif
	 /* iph->ip_id = ++ip_id; */
	 iph->ip_off = 0;
	 iph->ip_ttl = VRRP_MULTICAST_TTL;
#ifdef ENABLE_VRRP_AH
	 if (vr->AHencryption == 1)
	     iph->ip_p = IPPROTO_AH;
	 else
	     iph->ip_p = IPPROTO_VRRP;
#else
	 iph->ip_p = IPPROTO_VRRP;
#endif
	 iph->ip_src.s_addr = vr->vr_if->ip_addrs[0].s_addr;
	 iph->ip_dst.s_addr = inet_addr(VRRP_MULTICAST_IP);
	 iph->ip_sum = vrrp_misc_compute_checksum((u_short *) iph, iph->ip_hl << 2);
  	 
	return;
}

void 
vrrp_network_init_vrrphdr(char *buffer, struct vrrp_vr * vr)
{
	struct vrrp_hdr *vp;
	struct in_addr *addr;
	char           *password;
	int             cpt;

	vp = (struct vrrp_hdr *)buffer;
	vp->vrrp_v = VRRP_PROTOCOL_VERSION;
	vp->vrrp_t = VRRP_PROTOCOL_ADVERTISEMENT;
	vp->vr_id = vr->vr_id;
	vp->priority = vr->priority;
	vp->cnt_ip = vr->cnt_ip;
	vp->auth_type = vr->auth_type;
	vp->adv_int = vr->adv_int;
	addr = (struct in_addr *) & buffer[sizeof(struct vrrp_hdr)];
	for (cpt = 0; cpt < vr->cnt_ip; cpt++) {
		addr[cpt].s_addr = vr->vr_ip[cpt].addr.s_addr;
	}
	if (vr->auth_type == 1) {
		password = (char *)&addr[vr->cnt_ip];
		strncpy(password, vr->password, 8);
	}
	vp->csum = vrrp_misc_compute_checksum((u_short *) vp, vrrp_network_vrrphdr_len(vr));

	return;
}

char 
vrrp_network_send_advertisement(struct vrrp_vr * vr)
{
	u_char         *buffer;
#ifdef ENABLE_VRRP_AH
	u_int           len = sizeof(struct ip) + vrrp_ah_ahhdr_len(vr) + vrrp_network_vrrphdr_len(vr);
#else
	u_int           len = sizeof(struct ip) + vrrp_network_vrrphdr_len(vr);
#endif
	ssize_t		bytes = 0;

	buffer = (u_char *) malloc(len);
	bzero(buffer, len);

	vrrp_network_init_iphdr(buffer, vr);
#ifdef ENABLE_VRRP_AH
	/* add AH adding code */
	if (vr->AHencryption == 1) {
	    vrrp_ah_init_ahhdr(buffer,vr); 
	    vrrp_network_init_vrrphdr(&buffer[sizeof(struct ip)+vrrp_ah_ahhdr_len(vr)], vr); 
	    vrrp_ah_hmacmd5(buffer,vr);
	} else 
	    vrrp_network_init_vrrphdr(&buffer[sizeof(struct ip)+vrrp_ah_ahhdr_len(vr)], vr); 
#else
	vrrp_network_init_vrrphdr(&buffer[sizeof(struct ip)], vr);
#endif

	if (vr->fault)
		bytes = vrrp_network_send_packet(buffer, len, vr->sd, 0);
	else
		bytes = vrrp_network_send_packet(buffer, len, vr->sd, 1);

	if (bytes < 0) {
		syslog(LOG_ERR, "There is a big problem here !");
		vr->fault = 1;
		free(buffer);
		return -1;
	}
	vr->fault = 0;
	free(buffer);

	return 0;
}

int
vrrp_network_open_bpf(char *if_name)
{
        struct ifreq    ifr;
        int             n = 0;
        char            device[16];
        int             sd = 0;
        int             yes = 1;
   
        while ((sd <= 0) && (n < 100)) {
                snprintf(device, sizeof(device), "/dev/bpf%d", n++);
                sd = open(device, O_WRONLY);
        }
        if (sd < 0) { 
                syslog(LOG_ERR, "cannot found a valid /dev/bpf* entry, do you have bpf in kernel ?");
                syslog(LOG_ERR, "perhaps you've not created /dev entry on your chroot directory with bpf* entries");
                return -1;
        }
        bzero(&ifr, sizeof(ifr));
        strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
        if (ioctl(sd, BIOCSETIF, (caddr_t)&ifr) < 0) {
                syslog(LOG_ERR, "interface %s doesn't seem to exist, ioctl: %s\n", strerror(errno), ifr.ifr_name);
                syslog(LOG_ERR, "you must correct your configuration file with a good option for 'interface ='");
                return -1;
        }
        if (ioctl(sd, BIOCSHDRCMPLT, &yes) < 0) {
                syslog(LOG_ERR, "cannot do BIOCSHDRCMPLT: %s", strerror(errno));
                syslog(LOG_ERR, "something is terribly wrong, I can't continue");
                return -1;
        }

	return sd;
}

int 
vrrp_network_send_gratuitous_arp(char *if_name, struct ether_addr *ethaddr, struct in_addr addr)
{
        char buffer[ETHER_HDR_LEN + sizeof(struct arp_header)];
        struct ether_header *ethhdr = (struct ether_header *) buffer;
        struct arp_header *arph = (struct arp_header *) & buffer[ETHER_HDR_LEN];
	int sd;

        memset(ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
        bcopy(ethaddr, ethhdr->ether_shost, ETHER_ADDR_LEN);
        ethhdr->ether_type = htons(ETHERTYPE_ARP);
        bzero(arph, sizeof(*arph));
        arph->ar_hrd = htons(ARPHRD_ETHER);
        arph->ar_pro = htons(ETHERTYPE_IP);
        arph->ar_hln = ETHER_ADDR_LEN;
        arph->ar_pln = 4;
        arph->ar_op = htons(ARPOP_REQUEST);
        memcpy(arph->ar_sha, ethhdr->ether_shost, ETHER_ADDR_LEN);
	sd = vrrp_network_open_bpf(if_name);
        if (sd == -1)
                return -1;
        memcpy(arph->ar_spa, &addr, sizeof(struct in_addr));
        memcpy(arph->ar_tpa, &addr, sizeof(struct in_addr));
        if (write(sd, buffer, ETHER_HDR_LEN + sizeof(struct arp_header)) == -1) {
                syslog(LOG_ERR, "cannot write on socket descriptor sd: %s", strerror(errno));
		close(sd);
                return -1;
        }
	close(sd);

        return 0;
}

int
vrrp_network_send_gratuitous_arp_ips(struct vrrp_vr * vr, struct ether_addr * ethaddr)
{
        int             cpt = 0;
        struct in_addr  addrs[MAX_IP_ALIAS];
        int             size = MAX_IP_ALIAS;
        char            coderet = 0;

        bzero(addrs, sizeof(addrs));
        vrrp_misc_get_if_infos(vr->vr_if->if_name, NULL, addrs, &size);
        while (addrs[cpt].s_addr) {
                coderet = vrrp_network_send_gratuitous_arp(vr->vr_if->if_name, ethaddr, addrs[cpt]);
                syslog(LOG_ERR, "send gratuitous arp %s -> %x:%x:%x:%x:%x:%x", inet_ntoa(addrs[cpt]), ethaddr->octet[0], ethaddr->octet[1], ethaddr->octet[2], ethaddr->octet[3], ethaddr->octet[4], ethaddr->octet[5]);
                cpt++;
        }

        return coderet;
}

#define rtm rtmsg.rthdr
char 
vrrp_network_delete_local_route(struct in_addr addr)
{
	struct routemsg rtmsg;
	int             sd;

	sd = socket(PF_ROUTE, SOCK_RAW, 0);
	if (sd == -1) {
		close(sd);
		return -1;
	}
	bzero(&rtmsg, sizeof(rtmsg));
	rtm.rtm_type = RTM_DELETE;
	rtm.rtm_version = RTM_VERSION;
#ifdef __FreeBSD__
	rtm.rtm_flags = RTF_UP | RTF_HOST | RTF_LOCAL;
#endif
#if __FreeBSD_version < 800059
	rtm.rtm_flags |= RTF_WASCLONED;
#endif
#ifdef __NetBSD__
	rtm.rtm_flags = RTF_UP | RTF_HOST | RTF_CLONED;
#endif
	rtm.rtm_addrs = RTA_DST;
	rtm.rtm_msglen = sizeof(rtmsg);
	rtmsg.addr.sin_len = sizeof(rtmsg.addr);
	rtmsg.addr.sin_family = AF_INET;
	rtmsg.addr.sin_addr = addr;
	if (write(sd, &rtmsg, sizeof(rtmsg)) == -1) {
		close(sd);
		return -1;
	}
	close(sd);

	return 0;
}
