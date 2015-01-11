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
 * $Id: vrrp_thread.c,v 1.4 2004/03/05 22:06:45 spe Exp $
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "vrrp_thread.h"
#include "vrrp_moncircuit.h"

pthread_mutex_t pth_mutex, pth_mutex_monitor;

void 
vrrp_thread_mutex_lock(void)
{
	pthread_mutex_lock(&pth_mutex);

	return;
}

void 
vrrp_thread_mutex_unlock(void)
{
	pthread_mutex_unlock(&pth_mutex);

	return;
}

void vrrp_thread_mutex_lock_monitor(void)
{
	pthread_mutex_lock(&pth_mutex_monitor);

	return;
}

void vrrp_thread_mutex_unlock_monitor(void)
{
	pthread_mutex_unlock(&pth_mutex_monitor);

	return;
}

void *
vrrp_thread_launch_vrrprouter(void *args)
{
	int **args2 = (int **)args;
	struct vrrp_vr *vr = (struct vrrp_vr *)args2[0];
	sem_t *sem = (sem_t *)args2[1];
	int returnCode = 0;

	vr_ptr[vr_ptr_pos] = vr;
	vr_ptr_pos++;
	if (vr_ptr_pos == 255) {
		syslog(LOG_ERR, "cannot configure more than 255 VRID... exiting\n");
		exit(-1);
	}
	sem_post(sem);
	for (;;) {
		switch (vr->state) {
		case VRRP_STATE_INITIALIZE:
			returnCode = vrrp_state_initialize(vr);
			break;
		case VRRP_STATE_MASTER:
			returnCode = vrrp_state_master(vr);
			break;
		case VRRP_STATE_BACKUP:
			returnCode = vrrp_state_backup(vr);
			break;
		}
		if (returnCode < 0) {
			syslog(LOG_ERR, "vrid [%d] Cannot reach the correct state, disabled: %s\n", vr->vr_id, strerror(errno));
			pthread_exit(NULL);
		}
	}

	/* Normally never executed */
	return NULL;
}

char 
vrrp_thread_initialize(void)
{
	if (pthread_mutex_init(&pth_mutex, NULL) != 0) {
		syslog(LOG_ERR, "can't initialize thread for socket reading [ PTH_MUTEX, NULL ]");
		return -1;
	}
	if (pthread_mutex_init(&pth_mutex_monitor, NULL) != 0) {
		syslog(LOG_ERR, "can't initialize thread for socket reading [ PTH_MUTEX, NULL ]");
		return -1;
	}
	return 0;
}

char 
vrrp_thread_create_vrid(struct vrrp_vr * vr)
{
	pthread_t       pth;
	pthread_attr_t  pth_attr;
	sem_t		sem;
	void		*args[2];

        if (sem_init(&sem, 0, 0) == -1) {
		syslog(LOG_ERR, "can't initialize an unnamed semaphore [ SEM, 0, 0 ]");
		return -1;
	}
	if (pthread_attr_init(&pth_attr) != 0) {
		syslog(LOG_ERR, "can't initialize thread attributes [ PTH_ATTR ]");
		return -1;
	}
	if (pthread_attr_setdetachstate(&pth_attr, PTHREAD_CREATE_DETACHED) != 0) {
		syslog(LOG_ERR, "can't set thread attributes [ PTH_ATTR, PTHREAD_CREATE_DETACHED ]");
		return -1;
	}
	args[0] = vr;
	args[1] = &sem;
	if (pthread_create(&pth, &pth_attr, vrrp_thread_launch_vrrprouter, args) != 0) {
		syslog(LOG_ERR, "can't create new thread [ PTH, PTH_ATTR, VRRP_THREAD_READ_SOCKET ]");
		return -1;
	}
	sem_wait(&sem);
	sem_destroy(&sem);

	return 0;
}

int vrrp_thread_create_moncircuit(void)
{
	pthread_t	pth;
	pthread_attr_t	pth_attr;
	sem_t		sem;
	int		delay = VRRP_MONCIRCUIT_MONDELAY;
	void		*args[2];

	if (sem_init(&sem, 0, 0) == -1) {
		syslog(LOG_ERR, "can't initialize an unnamed semaphore [ SEM, 0, 0 ]");
		return -1;
	}
	if (pthread_attr_init(&pth_attr) != 0) {
		syslog(LOG_ERR, "can't initialize thread attributes [ PTH_ATTR ]");
		return -1;
	}
	if (pthread_attr_setdetachstate(&pth_attr, PTHREAD_CREATE_DETACHED) != 0) {
		syslog(LOG_ERR, "can't set thread attributes [ PTH_ATTR, PTHREAD_CREATE_DETACHED ]");
		return -1;
	}
	args[0] = &delay;
	args[1] = &sem;
	if (pthread_create(&pth, &pth_attr, vrrp_moncircuit_monitor_thread, args) != 0) {
		syslog(LOG_ERR, "can't create new thread [ PTH, PTH_ATTR, VRRP_THREAD_READ_SOCKET ]");
		return -1;
	}
	sem_wait(&sem);
	sem_destroy(&sem);

	return 0;
}
