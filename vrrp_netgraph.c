#include <netgraph.h>
#include <netgraph/ng_message.h>
#include <netgraph/ng_ether.h>
#include <netgraph/ng_eiface.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "vrrp_netgraph.h"
#include "vrrp_proto.h"
#include "vrrp_functions.h"

struct ng_mesg *vrrp_netgraph_get_node_list(int);

/* Function from FreeBSD sys/netgraph/ng_ether.c */
static void
ng_ether_sanitize_ifname(const char *ifname, char *name) {
	int i;
	for (i = 0; i < IFNAMSIZ; i++) {
		if (ifname[i] == '.' || ifname[i] == ':')
			name[i] = '_';
		else
			name[i] = ifname[i];
		if (name[i] == '\0')
			break;
	}
}

int vrrp_netgraph_open(int *ng_control_socket, int *ng_data_socket) {
	if (NgMkSockNode(NULL, ng_control_socket, ng_data_socket) < 0) {
		syslog(LOG_ERR, "cannot create a netgraph socket: %s", strerror(errno));
		return -1;
	}

	return 0;
}

void vrrp_netgraph_close(int ng_control_socket, int ng_data_socket) {
	close(ng_control_socket);
	close(ng_data_socket);

	return;
}

int vrrp_netgraph_bridge_create(char *ifname) {
	char sanifname[IFNAMSIZ];
	struct ngm_mkpeer mkp;
	struct ngm_name name;
	struct ngm_connect connect;
	char path[256];
	int ng_control_socket, ng_data_socket;

	if (vrrp_netgraph_open(&ng_control_socket, &ng_data_socket) < 0)
		return -1;

	/* ng_ether doesn't support ifname that includes '.' or ':' characters.
	 * It replaces them by '_', so the ng link names are renamed
	 * cf https://svnweb.freebsd.org/base?view=revision&revision=246245
	 * Copy/past the ng_ether_sanitize_ifname () logic here
	 */
	ng_ether_sanitize_ifname(ifname, sanifname);
	snprintf(mkp.type, sizeof(mkp.type), "bridge");
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), "lower");
	snprintf(mkp.peerhook, sizeof(mkp.peerhook), "link0");
	snprintf(path, sizeof(path), "%s:", sanifname);

	if (NgSendMsg(ng_control_socket, path, NGM_GENERIC_COOKIE, NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
		vrrp_netgraph_close(ng_control_socket, ng_data_socket);
		return -1;
	}

	snprintf(name.name, sizeof(name.name), "%s_%sbridge", VRRP_NETGRAPH_BASENAME, sanifname);
	snprintf(path, sizeof(path), "%s:lower", sanifname);
	if (NgSendMsg(ng_control_socket, path, NGM_GENERIC_COOKIE, NGM_NAME, &name, sizeof(name)) < 0) {
		vrrp_netgraph_close(ng_control_socket, ng_data_socket);
		return -1;
	}

	snprintf(connect.path, sizeof(connect.path), "%s_%sbridge:", VRRP_NETGRAPH_BASENAME, sanifname);
	snprintf(connect.ourhook, sizeof(connect.ourhook), "upper");
	snprintf(connect.peerhook, sizeof(connect.peerhook), "link1");
	snprintf(path, sizeof(path), "%s:", sanifname);
	if (NgSendMsg(ng_control_socket, path, NGM_GENERIC_COOKIE, NGM_CONNECT, &connect, sizeof(connect)) < 0) {
		vrrp_netgraph_close(ng_control_socket, ng_data_socket);
		return -1;
	}

	vrrp_netgraph_close(ng_control_socket, ng_data_socket);

	return 0;
}

int vrrp_netgraph_get_ethernet_address(int ng_control_socket, char *path, struct ether_addr *eaddr) {
	struct ng_mesg *ngmsg;

	if (NgSendMsg(ng_control_socket, path, NGM_EIFACE_COOKIE, NGM_EIFACE_GET_IFADDRS, NULL, 0) < 0)
		return -1;

	if (NgAllocRecvMsg(ng_control_socket, &ngmsg, NULL) < 0) {
		syslog(LOG_ERR, "cannot get netgraph answer: %s\n", strerror(errno));
		return -1;
	}

	/* XXX SANITY CHECK HERE */
	bcopy(ngmsg->data, eaddr, sizeof(*eaddr));

	free(ngmsg);
	return 0;
}

int vrrp_netgraph_set_ethernet_address(int ng_control_socket, char *path, struct ether_addr *eaddr) {
	if (NgSendMsg(ng_control_socket, path, NGM_EIFACE_COOKIE, NGM_EIFACE_SET, eaddr, sizeof(*eaddr)) < 0)
		return -1;

	return 0;
}

int vrrp_netgraph_create_eiface(char *ng_name, char *ether_name, struct ether_addr *ng_eaddr) {
	struct ngm_mkpeer mkp;
	struct ng_mesg *ngmsg;
	char path[256];
	char name[64];
	struct nodeinfo *ninfo;
	struct namelist *nlist;
	char found = 0;
	int ng_control_socket, ng_data_socket;

	if (vrrp_netgraph_open(&ng_control_socket, &ng_data_socket))
		return -1;

	snprintf(path, sizeof(path), ".");
	snprintf(mkp.type, sizeof(mkp.type), "eiface");
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), "ether");
	snprintf(mkp.peerhook, sizeof(mkp.peerhook), "ether");
	if (NgSendMsg(ng_control_socket, path, NGM_GENERIC_COOKIE, NGM_MKPEER, &mkp, sizeof(mkp)) < 0)
		return -1;

	vrrp_netgraph_close(ng_control_socket, ng_data_socket);

	if (vrrp_netgraph_open(&ng_control_socket, &ng_data_socket))
		return -1;

	/* Get node list for assigning a name to the newly created eiface */
	/* libnetgraph lacks of returning ID/name when creating nodes */
	/* it's a problem... */
	ngmsg = vrrp_netgraph_get_node_list(ng_control_socket);
	if (! ngmsg)
		return -1;

	nlist = (struct namelist *)ngmsg->data;
	ninfo = nlist->nodeinfo;
	while ((nlist->numnames > 0) && (! found)) {
		if (! strcmp(ninfo->type, "eiface")) {
			if (! strcmp(ninfo->name, ""))
				snprintf(ninfo->name, sizeof(ninfo->name), "ngeth0");
			if (! ninfo->hooks) {
				snprintf(path, sizeof(path), "[%X]:", ninfo->id);
				snprintf(ether_name, IFNAMSIZ, "%s", ninfo->name);
				if (vrrp_netgraph_set_ethernet_address(ng_control_socket, path, ng_eaddr) < 0) {
					syslog(LOG_ERR, "cannot set ethernet address to %s: %s\n", ninfo->name, strerror(errno));
					free(ngmsg);
					return -1;
				}
				snprintf(name, sizeof(name), "%s", ng_name);
				if (NgNameNode(ng_control_socket, path, name) < 0) {
					free(ngmsg);
					return -1;
				}
				found = 1;
			}
		}
		ninfo++;
		nlist->numnames--;
	}

	free(ngmsg);

	vrrp_netgraph_close(ng_control_socket, ng_data_socket);

	return 0;
}

int vrrp_netgraph_connect_eiface_to_bridge(int ng_control_socket, char *eiface_name, char *ifname, int *link_number) {
	struct ngm_connect connect;
	char path[256];
	char sanifname[IFNAMSIZ];

	NgSetDebug(10);
	ng_ether_sanitize_ifname(ifname, sanifname);

	snprintf(path, sizeof(path), "%s:", eiface_name);
	snprintf(connect.path, sizeof(connect.path), "%s_%sbridge:", VRRP_NETGRAPH_BASENAME, sanifname);
	snprintf(connect.ourhook, sizeof(connect.ourhook), "ether");
	snprintf(connect.peerhook, sizeof(connect.peerhook), "link%d", *link_number);

	if (NgSendMsg(ng_control_socket, path, NGM_GENERIC_COOKIE, NGM_CONNECT, &connect, sizeof(connect)) < 0) {
		syslog(LOG_ERR, "cannot connect path %s to bridge %s with link%d: %s\n", path, connect.path, *link_number, strerror(errno));
		return -1;
	}

	(*link_number)++;

	return 0;
}

struct ng_mesg *vrrp_netgraph_get_node_list(int ng_control_socket) {
	struct ng_mesg *ngmsg;

	if (NgSendMsg(ng_control_socket, ".", NGM_GENERIC_COOKIE, NGM_LISTNODES, NULL, 0) < 0) {
		syslog(LOG_ERR, "cannot send netgraph message: %s\n", strerror(errno));
		return NULL;
	}

	if (NgAllocRecvMsg(ng_control_socket, &ngmsg, NULL) < 0) {
		syslog(LOG_ERR, "cannot get netgraph answer: %s\n", strerror(errno));
		return NULL;
	}
	
	return ngmsg;
}

int vrrp_netgraph_create_virtualiface(struct vrrp_vr *vr) {
	char eiface_name[256];
	int ng_control_socket, ng_data_socket;

	snprintf(eiface_name, sizeof(eiface_name), "%s_vrid%d", VRRP_NETGRAPH_BASENAME, vr->vr_id);
	if (vrrp_netgraph_create_eiface(eiface_name, vr->viface_name, &vr->ethaddr) < 0) {
		syslog(LOG_ERR, "cannot create an eiface/ether netgraph interface: %s\n", strerror(errno));
		syslog(LOG_ERR, "ng_ether.ko is probably not loaded, use kldload ng_ether.ko before running freevrrpd\n");
		fprintf(stderr, "Please load ng_ether manually with kldload ng_ether.ko or add ng_ether_load=\"YES\" into /boot/loader.conf\n");
		return -1;
	}
	if (vrrp_netgraph_open(&ng_control_socket, &ng_data_socket) < 0)
		return -1;
	if (vrrp_netgraph_connect_eiface_to_bridge(ng_control_socket, eiface_name, vr->vr_if->if_name, &vr->bridge_link_number) < 0)
		return -1;

	vrrp_netgraph_close(ng_control_socket, ng_data_socket);

	return 0;
}

int vrrp_netgraph_shutdown_allnodes(void) {
	struct nodeinfo *ninfo;
	struct namelist *nlist;
	struct ng_mesg *ngmsg;
	char path[256];
	int ng_control_socket, ng_data_socket;

	if (vrrp_netgraph_open(&ng_control_socket, &ng_data_socket) < 0)
		return -1;

	ngmsg = vrrp_netgraph_get_node_list(ng_control_socket);
	if (! ngmsg)
		return -1;

	nlist = (struct namelist *)ngmsg->data;
	ninfo = nlist->nodeinfo;
	while (nlist->numnames > 0) {
		if (! strncmp(ninfo->name, VRRP_NETGRAPH_BASENAME, strlen(VRRP_NETGRAPH_BASENAME))) {
			snprintf(path, sizeof(path), "%s:", ninfo->name);
			vrrp_netgraph_shutdown(ng_control_socket, path);
		}
		ninfo++;	
		nlist->numnames--;
	}

	free(ngmsg);
	vrrp_netgraph_close(ng_control_socket, ng_data_socket);

	return 0;
}

int vrrp_netgraph_shutdown(int ng_control_socket, char *path) {
	if (NgSendMsg(ng_control_socket, path, NGM_GENERIC_COOKIE, NGM_SHUTDOWN, NULL, 0) < 0) {
		syslog(LOG_ERR, "cannot shutdown netgraph path %s: %s\n", path, strerror(errno));
		return -1;
	}

	return 0;
}
