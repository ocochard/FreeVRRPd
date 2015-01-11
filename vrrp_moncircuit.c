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
 * $Id: vrrp_moncircuit.c,v 1.6 2004/04/01 15:40:52 spe Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_media.h>
#include <errno.h>
#include <semaphore.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "vrrp_moncircuit.h"
#include "vrrp_define.h"

/*
 * Function that returns an integer that represent a status (carrier) of a
 * specified if_name interface transmited by argument
 * return -3: ioctl SIOCGIFMEDIA is not supported, disable moncircuits
 * return -2: interface is faulty or doesn't exist !
 * return -1: error
 * return  0: no carrier
 * return  1: ok, carrier, interface is working
 */
int vrrp_moncircuit_interface_status(int sd, char *if_name)
{
	struct ifmediareq ifmr;

	if (sd < 0) {
		syslog(LOG_ERR, "socket descriptor must be != -1");
		return -1;
	}
	bzero(&ifmr, sizeof(ifmr));
	strncpy(ifmr.ifm_name, if_name, sizeof(ifmr.ifm_name));

	if (ioctl(sd, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
		if (errno == EINVAL) {
			syslog(LOG_ERR, "your NIC doesn't support SIOCGIFMEDIA ioctl: %s", strerror(errno));
			return -3;
		}
		else
			syslog(LOG_ERR, "cannot do ioctl, intertface is faulty: %s", strerror(errno));
		return -2;
	}

	if (ifmr.ifm_status & IFM_AVALID) {
		if (ifmr.ifm_status & IFM_ACTIVE)
			return 1;
		else
			return 0;
	}

	/* Interface has no carrier cable problem ? */
	return 0;
}

void *vrrp_moncircuit_monitor_thread(void *args)
{
	int **args2 = (int **)args;
	int delay = *args2[0];
	sem_t *sem  = (sem_t *)args2[1];
	int numvrid, numvrid2;
	int cpt;
	int sd;
	int returnCode;

	sd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		syslog(LOG_ERR, "cannot open a DGRAM socket: %s", strerror(errno));
		pthread_exit(NULL);
	}
	sem_post(sem);
	for (;;) {
		numvrid = 0;
		while (vr_ptr[numvrid]) {
			vrrp_thread_mutex_lock_monitor();
			returnCode = vrrp_moncircuit_interface_status(sd, vr_ptr[numvrid]->vr_if->if_name);
			vrrp_thread_mutex_unlock_monitor();
			if (returnCode == -3) {
				vr_ptr[numvrid]->useMonitoredCircuits = 0;
				syslog(LOG_NOTICE, "monitored circuits engine disabled");
				pthread_exit(NULL);
			}
			if ((returnCode == 1) && (! vr_ptr[numvrid]->fault)) {
				if (vr_ptr[numvrid]->vr_if->nberrors < VRRP_MONCIRCUIT_MAX_ERRORS) {
					if (! vr_ptr[numvrid]->vr_if->alive) {
						vr_ptr[numvrid]->vr_if->alive = 1;
						syslog(LOG_ERR, "interface %s is alive again, reactivate it on VRRP", vr_ptr[numvrid]->vr_if->if_name);
						if (vr_ptr[numvrid]->vridsdeps) {
							numvrid2 = 0;
							while (vr_ptr[numvrid2]) {
								cpt = 0;
								while (vr_ptr[numvrid]->vridsdeps[cpt] != -1) {
									if ((vr_ptr[numvrid2]->vr_id == vr_ptr[numvrid]->vridsdeps[cpt])
									    && (vr_ptr[numvrid2]->vr_if->alive == -1)) {
										vr_ptr[numvrid2]->vr_if->alive = 1;
										syslog(LOG_ERR, "VRID %d (interface %s) has been reactivated due to dependance", vr_ptr[numvrid2]->vr_id, vr_ptr[numvrid2]->vr_if->if_name);
									}
									cpt++;
								}
								numvrid2++;
							}
						}
					}
					vr_ptr[numvrid]->vr_if->checksok++;
					if (vr_ptr[numvrid]->vr_if->checksok > vr_ptr[numvrid]->monitoredCircuitsClearErrorsCount) {
						vr_ptr[numvrid]->vr_if->nberrors = 0;
						vr_ptr[numvrid]->vr_if->checksok = 0;
						syslog(LOG_NOTICE, "all errors are cleared on interface %s", vr_ptr[numvrid]->vr_if->if_name);
					}
				}
				else {
					if (! vr_ptr[numvrid]->vr_if->reportsyslog) {
						syslog(LOG_ERR, "cannot reactivate interface %s, too much errors on it !", vr_ptr[numvrid]->vr_if->if_name);
						vr_ptr[numvrid]->vr_if->reportsyslog = 1;
					}
				}
			}
			else {
				if (vr_ptr[numvrid]->vr_if->alive == 1) {
					vr_ptr[numvrid]->vr_if->nberrors++;
					vr_ptr[numvrid]->vr_if->alive = 0;
					vr_ptr[numvrid]->vr_if->checksok = 0;
					syslog(LOG_ERR, "interface %s is faulty, deactivated from VRRP VRIDs", vr_ptr[numvrid]->vr_if->if_name);
					if (vr_ptr[numvrid]->vridsdeps) {
						numvrid2 = 0;
						while (vr_ptr[numvrid2]) {
							cpt = 0;
							while (vr_ptr[numvrid]->vridsdeps[cpt] != -1) {
								if ((vr_ptr[numvrid2]->vr_id == vr_ptr[numvrid]->vridsdeps[cpt])
								    && (vr_ptr[numvrid2]->vr_if->alive == 1)) {
									vr_ptr[numvrid2]->vr_if->alive = -1;
									vr_ptr[numvrid2]->vr_if->checksok = 0;
									syslog(LOG_ERR, "VRID %d (interface %s) has been deactivated due to dependance", vr_ptr[numvrid2]->vr_id, vr_ptr[numvrid2]->vr_if->if_name);
								}
								cpt++;
							}
							numvrid2++;
						}
					}
				}
			}
			numvrid++;
		}
		sleep(delay);
	}

	/* Never executed */
	pthread_exit(NULL);
}
