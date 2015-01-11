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
 * $Id: vrrp_state.c,v 1.18 2004/04/02 11:04:46 spe Exp $
 */

#include <stdlib.h>
#include <errno.h>
#include "vrrp_state.h"
#ifdef ENABLE_VRRP_AH
#include "vrrp_ah.h"
#endif

char 
vrrp_state_initialize(struct vrrp_vr * vr)
{
	if ((vr->priority == 255) && (! vr->fault)) {
		if (vrrp_state_set_master(vr) == -1)
			return -1;
	} else if (vrrp_state_set_backup(vr) == -1)
		return -1;

	return 0;
}

char 
vrrp_state_set_master(struct vrrp_vr * vr)
{
	int returnCode = 0;
	int counter = 0;

	vrrp_network_send_advertisement(vr);
	vrrp_thread_mutex_lock();
	vrrp_thread_mutex_lock_monitor();
	if (vrrp_interface_vripaddr_set(vr) == -1) {
		vrrp_thread_mutex_unlock_monitor();
		vrrp_thread_mutex_unlock();
		return -1;
	}
	if (vrrp_interface_up(vr->viface_name) < 0) {
		vrrp_thread_mutex_unlock_monitor();
		vrrp_thread_mutex_unlock();
		return -1;
	}

	/* Some NICs will reset (eg: bge/em) and wait some seconds before becoming carrier again */
	/* So we must wait for carrier */
	if (vr->useMonitoredCircuits) {
		for (counter = 0; (counter < vr->vr_if->carrier_timeout) && (returnCode != 1); counter++) {
			returnCode = vrrp_moncircuit_interface_status(vr->sd, vr->vr_if->if_name);
			sleep(1);
		}
	}

	vrrp_thread_mutex_unlock_monitor();
	vrrp_thread_mutex_unlock();
	if (vr->spanningTreeLatency) {
		syslog(LOG_NOTICE, "waiting %d seconds for the spanning tree latency", vr->spanningTreeLatency);
		sleep(vr->spanningTreeLatency);
	}
	if (vrrp_misc_calcul_tminterval(&vr->tm.adv_tm, vr->adv_int) == -1)
		return -1;
	vr->state = VRRP_STATE_MASTER;
	syslog(LOG_NOTICE, "server state vrid %d: master", vr->vr_id);
	printf("server state vrid %d: master\n", vr->vr_id);
	if (vr->master_script) {
		syslog(LOG_INFO, "[master] executing script %s\n", vr->master_script);
		if (system(vr->master_script) == -1)
			syslog(LOG_ERR, "[master] cannot execute script %s\n", vr->master_script);
		else
			syslog(LOG_INFO, "[master] script %s has been executed\n", vr->master_script);
	}

	return 0;
}

char 
vrrp_state_set_backup(struct vrrp_vr * vr)
{
	int returnCode = 0;
	int counter = 0;

	vrrp_thread_mutex_lock();
	vrrp_interface_vripaddr_delete(vr);
	vrrp_thread_mutex_lock_monitor();
	if (vrrp_interface_down(vr->viface_name) < 0) {
		vrrp_thread_mutex_unlock_monitor();
		vrrp_thread_mutex_unlock();
		return -1;
	}

	/* Some NICs will reset (eg: bge/em) and wait some seconds before becoming carrier again */
	/* So we must wait for carrier */
	if (vr->useMonitoredCircuits) {
		for (counter = 0; (counter < vr->vr_if->carrier_timeout) && (returnCode != 1); counter++) {
			returnCode = vrrp_moncircuit_interface_status(vr->sd, vr->vr_if->if_name);
			sleep(1);
		}
	}
	vrrp_thread_mutex_unlock_monitor();
	vrrp_thread_mutex_unlock();
	if (vr->spanningTreeLatency) {
		syslog(LOG_NOTICE, "waiting %d seconds for the spanning tree latency", vr->spanningTreeLatency);
		sleep(vr->spanningTreeLatency);
	}
	vr->skew_time = (256 - vr->priority) / 256;
	vr->master_down_int = (3 * vr->adv_int) + vr->skew_time;
	if (vrrp_misc_calcul_tminterval(&vr->tm.master_down_tm, vr->master_down_int) == -1)
		return -1;
	vr->state = VRRP_STATE_BACKUP;
	syslog(LOG_NOTICE, "server state vrid %d: backup", vr->vr_id);
	printf("server state vrid %d: backup\n", vr->vr_id);
	if (vr->backup_script) {
		syslog(LOG_INFO, "[backup] executing script %s\n", vr->backup_script);
		if (system(vr->backup_script) == -1)
			syslog(LOG_ERR, "[backup] cannot execute script %s\n", vr->backup_script);
		else
			syslog(LOG_INFO, "[backup] script %s has been executed\n", vr->backup_script);
	}

	return 0;
}

char 
vrrp_state_select(struct vrrp_vr * vr, struct timeval * interval)
{
	int             coderet;
	fd_set          readfds;

	FD_ZERO(&readfds);
	FD_SET(vr->sd, &readfds);
	coderet = select(FD_SETSIZE, &readfds, NULL, NULL, interval);

	return coderet;
}

/* Operation a effectuer durant l'etat master */
char 
vrrp_state_master(struct vrrp_vr * vr)
{
	int             coderet;
	u_char          packet[4096];
	ssize_t		packetSize;
	struct ip      *ipp = (struct ip *) packet;
#ifdef ENABLE_VRRP_AH
	struct vrrp_hdr *vrrph = (struct vrrp_hdr *) & packet[sizeof(struct ip)+vrrp_ah_ahhdr_len(vr)];
#else
	struct vrrp_hdr *vrrph = (struct vrrp_hdr *) & packet[sizeof(struct ip)];
#endif
	struct timeval  interval;
	struct sockaddr_in saddr;
	socklen_t len;

	for (;;) {
		if (vrrp_misc_calcul_tmrelease(&vr->tm.adv_tm, &interval) == -1)
			return -1;
		coderet = vrrp_state_select(vr, &interval);
		if (coderet > 0) {
			len = sizeof(struct sockaddr_in);
			packetSize = recvfrom(vr->sd, packet, sizeof(packet), 0, (struct sockaddr *)&saddr, &len);
			if (packetSize == -1) {
				syslog(LOG_ERR, "can't read on vr->sd socket descriptor: %s", strerror(errno));
				return -1;
			}
			if (vrrp_misc_check_vrrp_packet(vr, packet, packetSize) == -1)
				continue;
			if (vrrph->priority == 0) {
				if (vr->sd == -1)
					return -1;
				vrrp_network_send_advertisement(vr);
				if (vrrp_misc_calcul_tminterval(&vr->tm.adv_tm, vr->adv_int) == -1)
					return -1;
				continue;
			}
			if (vrrp_state_check_priority(vrrph, vr, ipp->ip_src) || (vr->fault) || (vr->vr_if->alive != 1)) {
				if (vrrp_state_set_backup(vr) == -1)
					return -1;
			}
			return 0;
		}
		if (coderet == 0) {
			if ((vr->vr_if->alive != 1) || (vr->fault)) {
				if (vrrp_state_set_backup(vr) == -1)
					return -1;
				return 0;
			}
			vrrp_network_send_advertisement(vr);
			if (vrrp_misc_calcul_tminterval(&vr->tm.adv_tm, vr->adv_int) == -1)
				return -1;
			continue;
		}
		if (coderet == -1) {
			syslog(LOG_ERR, "select on readfds fd_set failed: %s", strerror(errno));
			return -1;
		}
	}

	/* Normally never executed */
	return 0;
}

char 
vrrp_state_backup(struct vrrp_vr * vr)
{
	int             coderet;
	u_char          packet[4096];
	ssize_t		packetSize;
#ifdef ENABLE_VRRP_AH
	struct vrrp_hdr *vrrph = (struct vrrp_hdr *) & packet[sizeof(struct ip)+vrrp_ah_ahhdr_len(vr)];
#else
	struct vrrp_hdr *vrrph = (struct vrrp_hdr *) & packet[sizeof(struct ip)];
#endif
	struct timeval  interval;
	struct sockaddr_in saddr;
	socklen_t len;

	for (;;) {
		if (vrrp_misc_calcul_tmrelease(&vr->tm.master_down_tm, &interval) == -1)
			return -1;
		coderet = vrrp_state_select(vr, &interval);
		if (coderet > 0) {
			len = sizeof(struct sockaddr_in);
			packetSize = recvfrom(vr->sd, packet, sizeof(packet), 0, (struct sockaddr *)&saddr, &len);
			if (packetSize == -1) {
				syslog(LOG_ERR, "can't read on vr->sd socket descriptor: %s", strerror(errno));
				return -1;
			}
			if (vrrp_misc_check_vrrp_packet(vr, packet, packetSize) == -1)
				continue;
			if (vrrph->priority == 0) {
				if (vrrp_misc_calcul_tminterval(&vr->tm.master_down_tm, vr->skew_time) == -1)
					return -1;
				continue;
			}
			if (vr->preempt_mode == 0 || vrrph->priority >= vr->priority)
				if (vrrp_misc_calcul_tminterval(&vr->tm.master_down_tm, vr->master_down_int) == -1)
					return -1;
			continue;
		}
		if (coderet == -1) {
			syslog(LOG_ERR, "select on readfds fd_set failed: %s", strerror(errno));
			return -1;
		}
		if ((! coderet) && (vr->vr_if->alive == 1) && (! vr->fault)) {
			if (! vrrp_state_set_master(vr))
				return 0;
		}
		else
			if (vrrp_misc_calcul_tminterval(&vr->tm.master_down_tm, vr->master_down_int) == -1)
				return -1;
	}

	/* Normally never executed */
	return 0;
}

char 
vrrp_state_check_priority(struct vrrp_hdr * vrrph, struct vrrp_vr * vr, struct in_addr addr)
{
	if (vrrph->priority > vr->priority)
		return 1;
	if ((vrrph->priority == vr->priority) && (addr.s_addr > vr->vr_if->ip_addrs[0].s_addr))
		return 1;

	return 0;
}
