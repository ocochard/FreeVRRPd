#include <stdio.h>
#include <stdlib.h>
#include <netgraph.h>

int main(int argc, char **argv) {
	struct ngm_connect ngc;
	int ngs;
	int csp, dsp;
	char path[256];
	
	ngs = NgMkSockNode("prout", &csp, &dsp);
	snprintf(path, sizeof(path), "fv_vrid1_eiface:");
	snprintf(ngc.path, sizeof(ngc.path), "em0bridge:");
	snprintf(ngc.ourhook, sizeof(ngc.ourhook), "ether");
	snprintf(ngc.peerhook, sizeof(ngc.peerhook), "link2");
	if (NgSendMsg(csp, path, NGM_GENERIC_COOKIE, NGM_CONNECT, &ngc, sizeof(ngc)) < 0)
		perror("NgSendMsg");

	return 0;
}
