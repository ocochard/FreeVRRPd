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
 * $Id: vrrp_main.c,v 1.12 2004/03/30 23:13:00 spe Exp $
 */

#include <errno.h>
#include "vrrp_main.h"
#include "vrrp_conf.h"
#include "vrrp_thread.h"

/* Variables Globales */
/* addresses table of all struct vrrp_vr * initialized */
struct vrrp_vr *vr_ptr[VRRP_PROTOCOL_MAX_VRID+1];
/* actual position on this table */
u_char          vr_ptr_pos = 0;

void
vrrp_main_pre_init(struct vrrp_vr * vr)
{
	bzero(vr, sizeof(*vr));
	vr->priority = 100;
	vr->adv_int = VRRP_DEFAULT_ADV_INT;
	vr->preempt_mode = 1;
	vr->fault = 0;
	vr->useMonitoredCircuits = 1;
	vr->spanningTreeLatency = 0;
	vr->monitoredCircuitsClearErrorsCount = VRRP_MONCIRCUIT_CLEAR_ERRORS;
	vr->bridge_link_number = 2;

	return;
}

void
vrrp_main_post_init(struct vrrp_vr * vr, int firstime)
{
	int             size = MAX_IP_ALIAS;
	int		rc;

	vr->ethaddr.octet[0] = 0x00;
	vr->ethaddr.octet[1] = 0x00;
	vr->ethaddr.octet[2] = 0x5E;
	vr->ethaddr.octet[3] = 0x00;
	vr->ethaddr.octet[4] = 0x01;
	vr->ethaddr.octet[5] = vr->vr_id;
	vr->skew_time = (256 - vr->priority) / 256;
	vr->master_down_int = (3 * vr->adv_int) + vr->skew_time;
	if (firstime) {
		vrrp_misc_get_if_infos(vr->vr_if->if_name, &vr->vr_if->ethaddr, vr->vr_if->ip_addrs, &size);
		if (! vr->vr_if->ip_addrs[0].s_addr) {
			syslog(LOG_CRIT, "no IP address is configured on the real interface %s\n", vr->vr_if->if_name);
			syslog(LOG_CRIT, "cannot join multicast vrrp group without a real ip adress on %s\n", vr->vr_if->if_name);
			syslog(LOG_CRIT, "choose an IP address that is not used on any VRIDs and restart\n");
			syslog(LOG_CRIT, "you can set a private address for announcing VRRP packets (eg: 192.168.0.1/24)\n");
			syslog(LOG_CRIT, "exiting...\n");
			exit(-1);
		}
		vrrp_vlanlist_initialize(vr);
		vrrp_misc_get_vlan_infos(vr);
		vr->vr_if->nb_ip = size;
		vr->vr_if->alive = 1;
		vr->vr_if->nberrors = 0;
		vr->vr_if->reportsyslog = 0;
		vr->vr_if->carrier_timeout = VRRP_DEFAULT_CARRIER_TIMEOUT;
		vr->vr_if->checksok = 0;
	}
	vr->ioctl_sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (vr->ioctl_sd == -1) {
		syslog(LOG_WARNING, "cannot open socket: %s", strerror(errno));
		exit(-1);
	}

	/* Setting real interface in promiscuous mode */
	if (vrrp_interface_promiscuous(vr->vr_if->if_name) < 0) {
		syslog(LOG_CRIT, "cannot set interface %s in promiscuous mode\n", vr->vr_if->if_name);
		syslog(LOG_CRIT, "exiting...");
		exit(-1);
	}

	rc = vrrp_netgraph_bridge_create(vr->vr_if->if_name);
	if ((rc < 0) && (errno != EEXIST)) {
		syslog(LOG_CRIT, "cannot create a bridge device: %s", strerror(errno));
		syslog(LOG_CRIT, "aborting...");
		exit(-1);
	}
	rc = vrrp_netgraph_create_virtualiface(vr);
	if (rc < 0) {
		syslog(LOG_CRIT, "cannot create a virtual interface via netgraph: %s\n", strerror(errno));
		syslog(LOG_CRIT, "check that ng_socket, ng_ether, ng_eiface and ng_bridge are loaded\n");
		exit(-1);
	}

	return;
}

void
vrrp_main_print_struct(struct vrrp_vr * vr)
{
	int             cpt;

	fprintf(stderr, "VServer ID\t\t: %u\n", vr->vr_id);
	fprintf(stderr, "VServer PRIO\t\t: %u\n", vr->priority);
	fprintf(stderr, "VServer ETHADDR\t\t: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", vr->ethaddr.octet[0], vr->ethaddr.octet[1], vr->ethaddr.octet[2], vr->ethaddr.octet[3], vr->ethaddr.octet[4], vr->ethaddr.octet[5]);
	fprintf(stderr, "VServer CNT_IP\t\t: %u\n", vr->cnt_ip);
	fprintf(stderr, "VServer IPs\t\t:\n");
	for (cpt = 0; cpt < vr->cnt_ip; cpt++)
		fprintf(stderr, "\t%s\n", inet_ntoa(vr->vr_ip[cpt].addr));
	fprintf(stderr, "VServer ADV_INT\t\t: %u\n", vr->adv_int);
	fprintf(stderr, "VServer MASTER_DW_TM\t: %u\n", vr->master_down_int);
	fprintf(stderr, "VServer SKEW_TIME\t: %u\n", vr->skew_time);
	fprintf(stderr, "VServer State\t\t: %u\n", vr->state);
	fprintf(stderr, "Server IF_NAME\t\t: %s\n", vr->vr_if->if_name);
	fprintf(stderr, "Server NB_IP\t\t: %u\n", vr->vr_if->nb_ip);
	fprintf(stderr, "Server IPs\t\t:\n");
	for (cpt = 0; cpt < vr->vr_if->nb_ip; cpt++)
		fprintf(stderr, "\t%s\n", inet_ntoa(vr->vr_if->ip_addrs[cpt]));
	fprintf(stderr, "Server ETHADDR\t\t: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", vr->vr_if->ethaddr.octet[0], vr->vr_if->ethaddr.octet[1], vr->vr_if->ethaddr.octet[2], vr->vr_if->ethaddr.octet[3], vr->vr_if->ethaddr.octet[4], vr->vr_if->ethaddr.octet[5]);

	return;
}

void
init_copt(struct conf_options *copt)
{
	copt->conffile = VRRP_CONF_FILE_NAME;
	copt->foreground = 0;
	copt->chrootdir = NULL;

	return;
}

void
print_usage(void)
{
	printf("FreeVRRPd - VRRP daemon for FreeBSD\n");
	printf("Choose one of the following:\n");
	printf("-f : specify a path to a configuration file\n");
	printf("-F : launching in foreground\n");
	printf("-c : chroot to the specified directory\n");
	printf("-h : this screen ;)\n");
	printf("Found a bug ? mail me at olivier@FreeBSD.org\n");

	return;
}

void pidfile(void) {
	pid_t pid;
	FILE *fs;

	pid = getpid();
	fs = fopen("/var/run/freevrrpd.pid", "w");
	if (fs) {
		fprintf(fs, "%ld\n", (long)pid);
		fclose(fs);
	}
	else {
		syslog(LOG_ERR, "cannot open pid file for writing: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}

int
main(int argc, char **argv)
{
	FILE           *stream;
	int             coderet = 0;
	struct vrrp_vr *vr = NULL;
	struct conf_options copt;
	char ch;
	int firstime = 0;

	openlog("freevrrpd", LOG_PID, LOG_USER);
	init_copt(&copt);
	while ((ch = getopt(argc, argv, "f:Fc:h")) != -1) {
		switch (ch) {
			case 'F':
				copt.foreground = 1;
				break;
			case 'f':
				copt.conffile = (char *)calloc(strlen(optarg)+1, 1);
				strncpy(copt.conffile, optarg, strlen(optarg));
				break;
			case 'c':
				copt.chrootdir = (char *)calloc(strlen(optarg)+1, 1);
				strncpy(copt.chrootdir, optarg, strlen(optarg));
				break;
			case 'h':
			default:
				print_usage();
				exit(-1);
				break;
		}
	}
	if (copt.chrootdir)
		if (chroot(copt.chrootdir) == -1)
			syslog(LOG_ERR, "cannot chroot to the specified directory %s: %s", copt.chrootdir, strerror(errno));
	if ((stream = vrrp_conf_open_file(copt.conffile)) == NULL)
		return -1;
	if (! copt.foreground) {
		syslog(LOG_NOTICE, "launching daemon in background mode");
		if (daemon(0, 0) == -1) {
			syslog(LOG_ERR, "cannot transition to daemon mode: %s", strerror(errno));
			return -1;
		}
	}
	/*if (vrrp_netgraph_open(&ng_control_socket, &ng_data_socket) < 0) {
		syslog(LOG_ERR, "cannot open netgraph control socket: %s", strerror(errno));
		exit(-1);
	}*/

	/* Initialisation of struct vrrp_vr * adresses table */
	bzero(&vr_ptr, sizeof(vr_ptr));
	syslog(LOG_NOTICE, "initializing threads and all VRID");
	vrrp_thread_initialize();
	syslog(LOG_NOTICE, "reading configuration file %s", copt.conffile);
	while (!coderet) {
		vr = (struct vrrp_vr *)calloc(1, sizeof(struct vrrp_vr));
		vrrp_main_pre_init(vr);
		coderet = vrrp_conf_lecture_fichier(vr, stream);
		if (coderet < 0)
			return coderet;
		firstime = (! vr->vr_if->p) || (! vr->vr_if->d);
		vrrp_main_post_init(vr, firstime);
		if (firstime) {
			if (vrrp_list_initialize(vr, &vr->vr_if->ethaddr) < 0)
				return -1;
		}
		vrrp_interface_owner_verify(vr);
		if (vrrp_multicast_open_socket(vr) == -1)
			return -1;
		vrrp_main_print_struct(vr);
		if (vrrp_thread_create_vrid(vr) == -1)
			return -1;
	}
	vrrp_signal_initialize();
	/* Write a pid file in /var/run */
	pidfile();
	if (vr->useMonitoredCircuits) {
		if (vrrp_thread_create_moncircuit() == -1)
			return -1;
		syslog(LOG_NOTICE, "monitored circuits engine initialized");
	}
	else
		syslog(LOG_NOTICE, "monitored circuits engine disabled");

	pthread_exit(NULL);

	return 0;
}
