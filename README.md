# FreeVRRPd

A BSD-licensed implementation of the Virtual Router Redundancy Protocol (VRRP),
supporting both version 2 and version 3 of the protocol.

## Features

- VRRP v2 (RFC 2338), v3 (RFC 3768, RFC 5798)
- FreeBSD netgraph virtual interfaces (ngeth)
- Master/backup state machine with priority-based election
- Gratuitous ARP for fast failover (~3 seconds)
- Multicast advertisements via BPF
- Per-VRID master/backup transition scripts
- Multiple VRIDs per host
- Interface health monitoring (monitored circuits)

## Building

Requires FreeBSD with the `ng_ether` kernel module loaded:

```sh
kldload ng_ether
make
make install
```

All dependencies (`libnetgraph`, `libmd`, `libutil`, `pthreads`) are part of the
FreeBSD base system — no ports or packages needed.

## Configuration

Copy the sample configuration and edit for your environment:

```sh
cp /usr/local/etc/freevrrpd.conf.sample /usr/local/etc/freevrrpd.conf
```

See `freevrrpd.conf.sample` for annotated examples and `freevrrpd(8)` for full
documentation.

## Limitations

- **Cannot coexist with CARP.** FreeBSD's `if_carp.ko` registers a kernel-level
  handler for IP protocol 112 (shared by both CARP and VRRP). When loaded, it
  intercepts VRRP advertisements before they reach userspace, causing freevrrpd to
  miss peer announcements entirely. Ensure `if_carp` is not loaded (`kldunload if_carp`).

- **IPv4 only.** RFC 5798 defines VRRPv3 for IPv6, but this implementation does not
  support it.

- **FreeBSD only.** Depends on netgraph for virtual interface creation and BPF for
  gratuitous ARP injection.

- **Static configuration.** No runtime API — changes to `freevrrpd.conf` require a
  daemon restart.

## License

BSD 2-Clause. See [LICENSE](LICENSE) for details.

Original work by Sebastien Petit. Additional contributions by George V. Neville-Neil
and Rubicon Communications, LLC (Netgate).
