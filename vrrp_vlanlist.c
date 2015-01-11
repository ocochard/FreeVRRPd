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
 * $Id: vrrp_vlanlist.c,v 1.1 2004/03/06 18:33:57 spe Exp $
 */

#include <errno.h>
#include "vrrp_vlanlist.h"

/*
 * We use a double chained list with sentinels ---  --- |f|->|d|->NULL
 * NULL<-| |<-| | ---  ---
 */

char 
vrrp_vlanlist_initialize(struct vrrp_vr * vr)
{
	vr->vr_if->vlanp = (struct vrrp_vlan_list *) malloc(sizeof(*(vr->vr_if->vlanp)));
	vr->vr_if->vland = (struct vrrp_vlan_list *) malloc(sizeof(*(vr->vr_if->vland)));
	if (!vr->vr_if->vlanp || !vr->vr_if->vland) {
		syslog(LOG_ERR, "Can't allocate memory for vrrp_vlanlist_initialize: %s", strerror(errno));
		return -1;
	}
	bzero(vr->vr_if->vlanp, sizeof(*vr->vr_if->vlanp));
	bzero(vr->vr_if->vland, sizeof(*vr->vr_if->vland));
	vr->vr_if->vlanp->previous = NULL;
	vr->vr_if->vlanp->next = vr->vr_if->vland;
	vr->vr_if->vland->previous = vr->vr_if->vlanp;
	vr->vr_if->vland->next = NULL;
	/*if (vrrp_vlanlist_add(vr, vlan_ifname) == -1) {
		free(vr->vr_if->vlanp);
		free(vr->vr_if->vland);
		return -1;
	} */
	return 0;
}

/*
 * Add a new element in list
 */
char 
vrrp_vlanlist_add(struct vrrp_vr * vr, char *vlan_ifname)
{
	struct vrrp_vlan_list *n;

	if (!(n = (struct vrrp_vlan_list *) malloc(sizeof(*n)))) {
		syslog(LOG_ERR, "Can't allocate memory for vrrp_vlanlist_add: %s", strerror(errno));
		return -1;
	}
	bzero(n, sizeof(*n));
	strncpy(n->vlan_ifname, vlan_ifname, sizeof(n->vlan_ifname));
	n->previous = vr->vr_if->vland->previous;
	n->next = vr->vr_if->vland;
	vr->vr_if->vland->previous->next = n;
	vr->vr_if->vland->previous = n;

	return 0;
}

/*
 * Enleve un element de la liste
 */
char 
vrrp_vlanlist_delete(struct vrrp_vr * vr, char *vlan_ifname)
{
	struct vrrp_vlan_list *e = vr->vr_if->vlanp;

	while (e->next && strcpy(vlan_ifname, e->vlan_ifname))
		e = e->next;
	if (!e->next)
		return -1;
	e->next->previous = e->previous;
	e->previous->next = e->next;
	free(e);

	return 0;
}

char *
vrrp_vlanlist_get_first(struct vrrp_vr * vr)
{
	return vr->vr_if->vlanp->next->vlan_ifname;
}

/*
 * Renvoie l'adresse MAC du dernier element
 */
char *
vrrp_vlanlist_get_last(struct vrrp_vr * vr)
{
	return vr->vr_if->vland->previous->vlan_ifname;
}

void 
vrrp_vlanlist_destroy(struct vrrp_vr * vr)
{
	vr->vr_if->vland = vr->vr_if->vland->previous;
	while (vr->vr_if->vland != vr->vr_if->vlanp) {
		free(vr->vr_if->vland->next);
		vr->vr_if->vland = vr->vr_if->vland->previous;
	}
	free(vr->vr_if->vland);
	free(vr->vr_if->vlanp);

	return;
}
