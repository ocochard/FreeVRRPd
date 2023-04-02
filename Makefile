# $Id: Makefile,v 1.14 2004/04/02 13:12:52 spe Exp $

PROG=		freevrrpd
SRCS=		vrrp_misc.c vrrp_multicast.c vrrp_main.c vrrp_thread.c vrrp_state.c vrrp_network.c vrrp_interface.c vrrp_conf.c vrrp_signal.c vrrp_list.c vrrp_vlanlist.c vrrp_moncircuit.c vrrp_ah.c vrrp_netgraph.c
# Add -DENABLE_VRRP_AH to enable simple implementation of Authentication Header
CFLAGS=		-O3 -Wall -ansi -pedantic -fomit-frame-pointer -D_REENTRANT -Wall -ggdb
# use for AH only - currently in progress
#CFLAGS+=	-D_REENTRANT -Wall -ggdb -DENABLE_VRRP_AH -DKAME_BASED
#CFLAGS+=	-D_REENTRANT -Wall -ggdb -DENABLE_VRRP_AH
#LDADD=		-fomit-frame-pointer -ansi -lm -pthread -lipsec
# end of AH
LDADD=		-static -lm -lmd -pthread -lutil -lnetgraph
WARNS=		0
BINDIR=		/usr/local/sbin
MANDIR=		/usr/local/man/man

# Must write a man page
MAN=	freevrrpd.8
MAN8=	freevrrpd.8

beforeinstall:
	@echo "Installing files..."
	install -c -o root -g wheel -m 644 freevrrpd.conf.sample /usr/local/etc
	install -c -o root -g wheel -m 755 freevrrpd.sh.sample /usr/local/etc/rc.d
	@echo "#####################################################################"
	@echo "# !! WARNING !! You must copy /usr/local/etc/vrrpd.conf.sample to   #"
	@echo "# /usr/local/etc/vrrpd.conf and configure /usr/local/etc/vrrpd.conf #"
	@echo "# before running vrrpd. to run vrrpd type /usr/local/sbin/vrrpd  #"
	@echo "#####################################################################"

.include <bsd.prog.mk>
