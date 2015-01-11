/* $Id: vrrp_ah.h,v 1.8 2004/04/05 10:04:01 spe Exp $ 
 * MAGIC HEADER $#@!$#!@$!@$@!# :)
 */
#ifndef __VRRP_AH_H__
#define __VRRP_AH_H__
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifdef KAME_BASED
#include <netinet6/ipsec.h>
#include <net/pfkeyv2.h>
#include <netkey/keydb.h>
#include <netkey/key_debug.h>
#endif /* end of KAME BASED */
/* #include "md5.h" */

#define HMAC_MD596_SIZE 12

/* AH header struct for a keepalived implementation */
typedef struct ah_header {
    char next;		    /* must be 112 for IPPROTO_VRRP */
    char length;	    /* must be 3 (96 bits tronqued MD5 sum */
    unsigned short zero;
    int spi;		    /* will store the VIP of the current vrid */
    int seq;
    char auth[HMAC_MD596_SIZE];	    /* authentication data MD5 sum */
} ah_t;

#ifdef KAME_BASED
#define VRRP_OUT_POLICY "out ipsec ah/transport//require"
#define VRRP_IN_POLICY "in ipsec ah/transport//require"
#define VRRP_ADDRESS "224.0.0.18"
#define HOST_MASK 32
#define IPSEC_IPPROTO_VRRP 112
#define IPSEC_IPPROTO_ANY 255

/* KAME based AH function headers */
struct addrinfo * parse_addr(char *host, char *port);
int setkeymsg(struct sadb_msg *msg, unsigned int type, unsigned int satype, size_t l);
int setvarbuf(char *buf, int *off, struct sadb_ext *ebuf, int elen, caddr_t vbuf, int vlen);
int vrrp_pfkey_open(void);
int vrrp_pfkey_close(int fd);
int vrrp_ah_set_outpolicy(int fd, char *src);
int vrrp_ah_rm_outpolicy(int fd, char *src);
int vrrp_ah_set_inpolicy(int fd, char *src);
int vrrp_ah_rm_inpolicy(int fd, char *src);
int vrrp_ah_spd(int fd, char *src_addr, char *ah_policy, unsigned int cmd);

#else

/* simple AH functions headers */
int vrrp_ah_check_ahhdr(char *buffer, struct vrrp_vr *vr);
void vrrp_ah_init_ahhdr(unsigned char *buffer, struct vrrp_vr *vr);
void vrrp_ah_hmacmd5(unsigned char *buffer, struct vrrp_vr *vr);
#endif /* end of KAME_BASED */
int vrrp_ah_ahhdr_len(struct vrrp_vr *vr);
void hmac_md5(unsigned char *text, int text_len, unsigned char *key, int key_len, caddr_t digest);
int hexdump(unsigned char *zone, int len);

#endif
