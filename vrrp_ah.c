/*
 * Copyright (c) 2003 BurnesOnLine <bol@b0l.org>
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
 * $Id: vrrp_ah.c,v 1.13 2004/04/04 19:45:46 rival Exp $  
 *
 * MISC COMMENTS :
 * FreeVRRPd project AH implementation using KAME based ipsec stack.
 * tested on :
 *    FreeBSD
 *    NetBSD
 * should work on :
 *    Linux 2.6 or KAME based linux ipsec stack
 *
 * this code use KAME not fully implemented :
 * RFC 2367 - PF_KEY Key Management API, Version 2
 *
 * AUTHORS:
 * this is a working and almost clean "HACK"  :)
 * problem is, we cant set socket wide SPD and SAD
 * need to work out with KAME project to know exactly 
 * the procedure to make process wide changes and NOT
 * host wide changes.
 *
 * b0l.
 * 
 */
#include "vrrp_proto.h"
#include "vrrp_ah.h"
#include "md5.h"

#ifdef ENABLE_VRRP_AH
#ifdef KAME_BASED
/* special struct */
typedef enum {
    HMAC_MD5 = 2,	      /* 128 bits */
    HMAC_SHA1 = 3,	      /* 160 bits */
    HMAC_NULL,
    HMAC_SHA2_256,	      /* 256 bits */
    HMAC_SHA2_384,	      /* 384 bits */
    HMAC_SHA2_512,	      /* 512 bits */
    HMAC_RIPEMD160,	      /* 160 bits */
    AES_XCBC_MAC	      /* 128 bits */
} alg_t;

typedef struct algorithm {
    alg_t type;
    size_t keysize;
} algorithm_t;

algorithm_t algos[] = {
    { HMAC_MD5, 128 },
    { HMAC_SHA1, 160 },
    { HMAC_NULL, 0 },
    { HMAC_SHA2_256, 256 },
    { HMAC_SHA2_384, 384 },
    { HMAC_SHA2_512, 512 },
    { HMAC_RIPEMD160, 160 },
    { AES_XCBC_MAC, 128 }
};

/* what we need 
   ipsec (4)
   setsockopt(2)  * per socket behavior *
   sysctl(3) * host wide *
   ipsec_set_policy(3) * IPsec Policy Control Library (libipsec, -lipsec) *
   */

/* STOLEN FROM FreeBSD setkey.c :) */
struct addrinfo * parse_addr(char *host, char *port) {
	struct addrinfo hints, *res = NULL;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;		/*dummy*/
	hints.ai_protocol = IPPROTO_UDP;	/*dummy*/
	hints.ai_flags = 0;
	error = getaddrinfo(host, port, &hints, &res);
	if (error != 0) {
		perror(gai_strerror(error));
		return NULL;
	}
	return res;
}

int setkeymsg(struct sadb_msg *msg, unsigned int type, unsigned int satype, size_t l) {

	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = type;
	msg->sadb_msg_errno = 0;
	msg->sadb_msg_satype = satype;
	msg->sadb_msg_reserved = 0;
	msg->sadb_msg_seq = 0;
	msg->sadb_msg_pid = getpid();
	msg->sadb_msg_len = PFKEY_UNIT64(l);
	return 0;
}

int setvarbuf(char *buf, int *off, struct sadb_ext *ebuf, int elen, caddr_t vbuf, int vlen) {
	memset(buf + *off, 0, PFKEY_UNUNIT64(ebuf->sadb_ext_len));
	memcpy(buf + *off, (caddr_t)ebuf, elen);
	memcpy(buf + *off + elen, vbuf, vlen);
	(*off) += PFKEY_ALIGN8(elen + vlen);
	return 0;
}

/* WE NEED :
setkeymsg_spdaddr(type, upper, policy, srcs, splen, dsts, dplen)
*/

/* open the PF_KEY socket */
int vrrp_pfkey_open(void) {
    int key_fd;

    /* opening PF_KEY API */
    key_fd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    if (key_fd < 0) {
	perror("socket(PF_KEY)");
	return key_fd;
    }

    return key_fd;
}

/* close PF_KEY socket */
int vrrp_pfkey_close(int fd) {
    int rc = 0;
    rc = close(fd);
    return rc;
}

/* return -1 on failure, 0 on success */
int vrrp_ah_set_outpolicy(int fd, char *src) {
    int rc = 0;

    rc = vrrp_ah_spd(fd, src, VRRP_OUT_POLICY, SADB_X_SPDADD);
    if (rc < 0) {
	perror("VRRP_OUT_POLICY setup failed!\n");
	rc = -1;
    }
    return rc;
}

/* return -1 on failure, 0 on success */
int vrrp_ah_rm_outpolicy(int fd, char *src) {
    int rc = 0;

    rc = vrrp_ah_spd(fd, src, VRRP_OUT_POLICY, SADB_X_SPDDELETE);
    if (rc < 0) {
	perror("VRRP_OUT_POLICY removal failed\n");
	rc = -1;
    }
    return rc;
}

/* return -1 on failure, 0 on success */
int vrrp_ah_set_inpolicy(int fd, char *src) {
    int rc = 0;

    rc = vrrp_ah_spd(fd, src, VRRP_IN_POLICY, SADB_X_SPDADD);
    if (rc < 0) {
	perror("VRRP_IN_POLICY setup failed\n");
	rc = -1;
    }
    return rc;
}

/* return -1 on failure, 0 on success */
int vrrp_ah_rm_inpolicy(int fd, char *src) {
    int rc = 0;

    rc = vrrp_ah_spd(fd, src, VRRP_IN_POLICY, SADB_X_SPDDELETE);
    if (rc < 0) {
	perror("VRRP_IN_POLICY setup failed\n");
	rc = -1;
    }
    return rc;
}

/* return number of bytes sent to PF_KEY socket/in-kernel */
int vrrp_ah_spd(int fd, char *src_addr, char *ah_policy, unsigned int cmd) {
    /* lets see if it works */
    char *policy;
    int policy_len;
    const int bufsiz = 128 * 1024;
    char * buf = (char *) malloc (bufsiz * sizeof(char));
    struct sadb_msg *msg;
    struct sadb_address m_addr;
    struct sockaddr *sa; 
    struct addrinfo *src, *dst;
    int m_size;
    int salen;
    int rc;

    /* sanity checks */
    if (!buf) {
	fprintf(stderr,"could not allocate memory\n");
	return -1;
    }

    /* prepare the policy */
    policy = ipsec_set_policy(VRRP_OUT_POLICY, strlen(VRRP_OUT_POLICY));
    if (!policy) {
	perror("ipsec_set_policy()");
	return -1;
    }

    policy_len = ipsec_get_policylen(policy);
    if (policy_len < 0) {
	perror("ipsec_get_policylen()");
	return -1;
    }

    /* clearing everything, don't want this bugs to happen again */
    memset(buf,0,bufsiz);
    memset(&m_addr, 0, sizeof(m_addr));

    /* building PF_KEY msg */
    msg = (struct sadb_msg *) buf;
    setkeymsg(msg,(unsigned int)cmd,SADB_SATYPE_UNSPEC, 0);
    m_size = sizeof(struct sadb_msg);

    /* copying the policy */
    memcpy(buf+m_size, policy, policy_len);
    m_size += policy_len;

    /* parsing from / to */
    src = parse_addr(src_addr, 0);
    if (!src) {
	free(policy);
	free(buf);
	return -1;
    }

    dst = parse_addr(VRRP_ADDRESS, 0);
    if (!dst) {
	free(policy);
	freeaddrinfo(src);
	free(buf);
	return -1;
    }

    /* SOURCE SETUP */
    sa = src->ai_addr;
    salen = src->ai_addr->sa_len;
    m_addr.sadb_address_len = PFKEY_UNIT64(sizeof(m_addr)+PFKEY_ALIGN8(salen));
    m_addr.sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
    m_addr.sadb_address_proto = (unsigned int)IPSEC_IPPROTO_ANY;
    m_addr.sadb_address_prefixlen = HOST_MASK; 
    m_addr.sadb_address_reserved = 0;

    setvarbuf(buf, &m_size, (struct sadb_ext *)&m_addr,sizeof(m_addr),(caddr_t)sa, salen);

    /* DESTINATION SETUP */
    sa = dst->ai_addr;
    salen = src->ai_addr->sa_len;
    m_addr.sadb_address_len = PFKEY_UNIT64(sizeof(m_addr)+PFKEY_ALIGN8(salen));
    m_addr.sadb_address_exttype = SADB_EXT_ADDRESS_DST;
    m_addr.sadb_address_proto = (unsigned int)IPSEC_IPPROTO_ANY;
    m_addr.sadb_address_prefixlen = HOST_MASK; /* (splen >= 0 ? -1 : plen ); */
    m_addr.sadb_address_reserved = 0;

    setvarbuf(buf, &m_size, (struct sadb_ext *)&m_addr,sizeof(m_addr),(caddr_t)sa, salen);

    msg->sadb_msg_len = PFKEY_UNIT64(m_size);

    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsiz, sizeof(bufsiz));
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsiz, sizeof(bufsiz));

    rc = send(fd, buf, m_size, 0);
    if (rc < 0)
	perror("could not add entry to SPD: send()");

    free(policy);
    free(buf);
    freeaddrinfo(src);
    freeaddrinfo(dst);
    return rc;
}



/* status = setkeymsg_add(SADB_ADD, $5, $3, $4); */
/* DO NOT FORGET TO CLEAN THOSE FUKING LOCAL STRUCTURE 2 DAYS LOST $#@$!@#$#@!
 * */
int vrrp_ah_sad(int fd, char *src_addr, alg_t algo, char *key) {
    const int bufsiz = 128 * 1024;
    char * buf = (char *) malloc (bufsiz * sizeof(char));
    struct sadb_msg *msg;
    struct sadb_address m_addr;
    struct sockaddr *sa; 
    struct addrinfo *src, *dst, *s;
    int m_size;
    int salen;
    int rc;
    /* ADDED */
    int len;
    char * p_alg_auth = "hmac-sha1";
    char * p_key_auth = "12345678901234567890";
    int p_key_auth_len = strlen(p_key_auth);
    struct sadb_key m_key;
    struct sadb_sa m_sa;
    struct sadb_x_sa2 m_sa2;
    struct sadb_lifetime m_lt;

    msg = (struct sadb_msg *) buf;

    /* clearing the allocated data */
    memset(buf,0,bufsiz);

    setkeymsg(msg, SADB_ADD, SADB_SATYPE_AH, 0);
    /* setkeymsg(msg, SADB_DELETE, SADB_SATYPE_AH, 0); */

    m_size = sizeof(struct sadb_msg);
    /* HACK HACK */
    /* hexdump(msg,m_size); */

    m_key.sadb_key_len = PFKEY_UNIT64(sizeof(m_key) + PFKEY_ALIGN8(p_key_auth_len));
    m_key.sadb_key_exttype = SADB_EXT_KEY_AUTH;
    m_key.sadb_key_bits = p_key_auth_len * 8;
    m_key.sadb_key_reserved = 0;
    
    setvarbuf(buf, &m_size, (struct sadb_ext *)&m_key,sizeof(m_key),(caddr_t)p_key_auth, p_key_auth_len);

    /*
    u_int slen = sizeof(struct sadb_lifetime);
    m_lt.sadb_lifetime_len = PFKEY_UNIT64(slen);
    m_lt.sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
    m_lt.sadb_lifetime_allocations = 0;
    m_lt.sadb_lifetime_bytes = 0;
    m_lt.sadb_lifetime_addtime = 0;
    m_lt.sadb_lifetime_usetime = 0;

    memcpy(buf + m_size, &m_lt, slen);
    m_size += slen; 
    */

    /*
    m_key.sadb_key_len = PFKEY_UNIT64(sizeof(m_key) + PFKEY_ALIGN8(p_key_auth_len));
    m_key.sadb_key_exttype = SADB_EXT_KEY_AUTH;
    m_key.sadb_key_bits = p_key_auth_len * 8;
    m_key.sadb_key_reserved = 0;

    setvarbuf(buf, &m_size, (struct sadb_ext *)&m_key, sizeof(m_key), (caddr_t)p_key_auth, p_key_auth_len);
    */

    len = sizeof(struct sadb_sa);
    m_sa.sadb_sa_len = PFKEY_UNIT64(len);
    m_sa.sadb_sa_exttype = SADB_EXT_SA;
    m_sa.sadb_sa_spi = htonl(0x2710);
    m_sa.sadb_sa_replay = 0;
    m_sa.sadb_sa_state = 0;
    m_sa.sadb_sa_auth = 3; /* hmac-sha1 */
    m_sa.sadb_sa_encrypt = 0; /* no encryption yet */
    m_sa.sadb_sa_flags = 64; /* BUG HERE */

    memcpy(buf + m_size, &m_sa, len);
    m_size += len;

    bzero(&m_sa2, sizeof(struct sadb_x_sa2));

    len = sizeof(struct sadb_x_sa2);
    printf("len: %x  exttype: %x\n",PFKEY_UNIT64(len), SADB_X_EXT_SA2);
    m_sa2.sadb_x_sa2_len = PFKEY_UNIT64(len);
    m_sa2.sadb_x_sa2_exttype = SADB_X_EXT_SA2;
    m_sa2.sadb_x_sa2_mode = IPSEC_MODE_ANY; 
    m_sa2.sadb_x_sa2_reqid = 0;

    memcpy(buf + m_size, &m_sa2, len);
    m_size += len; 

    /* parsing from / to */
    src = parse_addr(src_addr, 0);
    if (!src) {
	free(buf);
	return -1;
    }

    dst = parse_addr(VRRP_ADDRESS, 0);
    if (!dst) {
	freeaddrinfo(src);
	free(buf);
	return -1;
    }

    /* SOURCE SETUP */
    for (s = src; s; s = s->ai_next) {
	sa = s->ai_addr;
	salen = s->ai_addr->sa_len; /* POSSIBLE BUG */
	m_addr.sadb_address_len = PFKEY_UNIT64(sizeof(m_addr)+PFKEY_ALIGN8(salen));
	m_addr.sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
	m_addr.sadb_address_proto = (unsigned int)IPSEC_ULPROTO_ANY;
	m_addr.sadb_address_prefixlen = HOST_MASK; /* (splen >= 0 ? -1 : plen ); */
	m_addr.sadb_address_reserved = 0; 
	setvarbuf(buf, &m_size, (struct sadb_ext *)&m_addr,sizeof(m_addr),(caddr_t)sa, salen);
    }

    /* DESTINATION SETUP */
    sa = dst->ai_addr;
    salen = dst->ai_addr->sa_len;
    m_addr.sadb_address_len = PFKEY_UNIT64(sizeof(m_addr)+PFKEY_ALIGN8(salen));
    m_addr.sadb_address_exttype = SADB_EXT_ADDRESS_DST;
    m_addr.sadb_address_proto = (unsigned int)IPSEC_ULPROTO_ANY;
    m_addr.sadb_address_prefixlen = HOST_MASK; /* (splen >= 0 ? -1 : plen ); */
    m_addr.sadb_address_reserved = 0;

    setvarbuf(buf, &m_size, (struct sadb_ext *)&m_addr,sizeof(m_addr),(caddr_t)sa, salen);

    msg->sadb_msg_len = PFKEY_UNIT64(m_size);

    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsiz, sizeof(bufsiz));
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsiz, sizeof(bufsiz));

    rc = send(fd, buf, m_size, 0);
    if (rc < 0)
	perror("could not add entry to SAD: send()");

    free(buf);
    freeaddrinfo(src);
    freeaddrinfo(dst);
    return rc;
}

#else
/* The simple implementation based on keepalived draft */
void vrrp_ah_init_ahhdr(unsigned char *buffer, struct vrrp_vr *vr) {
    struct ip *ip;
    struct ah_header *ah;

    ip = (struct ip *) buffer;
    ah = (struct ah_header *) (buffer+sizeof(struct ip));
    ah->next = IPPROTO_VRRP;
    ah->length = 0x04;
    ah->zero = 0x0000;
    ah->spi = htonl(vr->vr_if->ip_addrs[0].s_addr);
    ah->seq = htonl(1);
    /* clean first */
    memset(ah->auth,0,sizeof(ah->auth));

    return;
}

void vrrp_ah_hmacmd5(unsigned char *buffer, struct vrrp_vr *vr) {
    struct ip *ip;
    struct ah_header *ah;
    unsigned char md5[16];

    ip = (struct ip *) buffer;
    ah = (struct ah_header *) (buffer+sizeof(struct ip));

    /* clear md5 */
    memset(md5,0,sizeof(md5));

    /* hexdump(md5,sizeof(md5)); */
    /* lets compute digest */
    hmac_md5(buffer, (sizeof(struct ip)+sizeof(struct ah_header)+sizeof(struct vrrp_hdr)), (unsigned char *)vr->password, strlen(vr->password), md5);
    /* hexdump(md5,sizeof(md5)); */

    /* copy it */
    memcpy(ah->auth, md5, 12);

    return;
}

/* return 0 if packet is valid, -1 else */
int vrrp_ah_check_ahhdr(char *buffer, struct vrrp_vr *vr) {
    struct ah_header *ah;
    unsigned char recv_authdata[HMAC_MD596_SIZE], comp_authdata[HMAC_MD596_SIZE+4];

    ah = (struct ah_header *) buffer;
    if (ah->next != IPPROTO_VRRP)
	return -1;
    if (ah->length != 0x04)
	return -1;
    /*
    if (ah->seq < vr->ahctx->seq) 
	return -1;
    else 
	vr->ahctx->seq = ah->seq;
	*/

    /* save auth data and rebuild hmac to see if it match */
    memcpy(recv_authdata,(caddr_t)ah->auth,HMAC_MD596_SIZE);
    memset(ah->auth,0, HMAC_MD596_SIZE);
    hmac_md5((unsigned char *)buffer, sizeof(struct ip)+sizeof(struct ah_header)+sizeof(struct vrrp_hdr), vr->password, strlen(vr->password), comp_authdata);

    if (memcmp(recv_authdata, comp_authdata, HMAC_MD596_SIZE) == 0)
	return 0;

    printf("packet invalid!!!\n");
    return -1;
}
#endif /* end of ifdef KAME_BASED */
#endif /* endof ENABLE_VRRP_AH */


int vrrp_ah_ahhdr_len(struct vrrp_vr *vr) {
#ifdef ENABLE_VRRP_AH
    if (vr->AHencryption == 1)
	return (sizeof(struct ah_header));
#endif
    return 0;
}


/*
RFC 2104 define this.
unsigned char*  text;                * pointer to data stream *
int             text_len;            * length of data stream *
unsigned char*  key;                 * pointer to authentication key *
int             key_len;             * length of authentication key *
caddr_t         digest;              * caller digest to be filled in *
*/
void hmac_md5(unsigned char *text, int text_len, unsigned char *key, int key_len, caddr_t digest) {
        MD5_CTX context,tctx;
        unsigned char k_ipad[65];    /* inner padding - key XORd with ipad */
        unsigned char k_opad[65];    /* outer padding - key XORd with opad */
        unsigned char tk[16];
        int i;

        /* if key is longer than 64 bytes reset it to key=MD5(key) */
        if (key_len > 64) {

                MD5Init(&tctx);
                MD5Update(&tctx, key, key_len);
                MD5Final(tk, &tctx);

                key = tk;
                key_len = 16;
        }

        /*
         * the HMAC_MD5 transform looks like:
         *
         * MD5(K XOR opad, MD5(K XOR ipad, text))
         *
         * where K is an n byte key
         * ipad is the byte 0x36 repeated 64 times
         * opad is the byte 0x5c repeated 64 times
         * and text is the data being protected
         */

        /* start out by storing key in pads */
        bzero( k_ipad, sizeof k_ipad);
        bzero( k_opad, sizeof k_opad);
        bcopy( key, k_ipad, key_len);
        bcopy( key, k_opad, key_len);

        /* XOR key with ipad and opad values */
        for (i=0; i<64; i++) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }
        /* perform inner MD5 */
        MD5Init(&context);                   /* init context for 1st pass */
        MD5Update(&context, k_ipad, 64);      /* start with inner pad */
        MD5Update(&context, text, text_len); /* then text of datagram */
        MD5Final(digest, &context);          /* finish up 1st pass */

        /* perform outer MD5 */
	
        MD5Init(&context);                   /* init context for 2nd */

        MD5Update(&context, k_opad, 64);     /* start with outer pad */
        MD5Update(&context, digest, 16);     /* then results of 1st hash */
        MD5Final(digest, &context);          /* finish up 2nd pass */
}

/* Hexdumping on screen in a fancy format for debuging purposes */
int hexdump(unsigned char *zone, int len) {
    int rc=0,i;
    unsigned char *ptr;

    ptr = zone;
    fprintf(stderr,"-- hexdump at %p (%d bytes long) --",zone,len);
    for( i = 0 ;i < len;i++) {
	if((i%16)==0)
	    fprintf(stderr,"\n%p ",ptr+i);
	if((i%8)==0)
	    fprintf(stderr," ");
	fprintf(stderr,"0x%.2x ",*(ptr+i));
    }
    fprintf(stderr,"\n");
    return rc;
}
