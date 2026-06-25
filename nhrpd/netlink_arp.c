// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP netlink/neighbor table arpd code
 * Copyright (c) 2014-2016 Timo Teräs
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef GNU_LINUX
#include <linux/rtnetlink.h>
#endif

#include <fcntl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <linux/netlink.h>
#include <linux/neighbour.h>
#include <linux/netfilter/nfnetlink_log.h>

#include "frrevent.h"
#include "stream.h"
#include "prefix.h"
#include "nhrpd.h"
#include "netlink.h"
#include "znl.h"

/* The unicast (redirect / traffic-indication) NFLOG group. The actual NFLOG
 * socket is shared with the multicast OIL snoop and owned by
 * nhrp_multicast.c (nhrp_nflog_resync); see the comment there for why a single
 * socket is required. netlink_log_indication() below is the per-packet handler
 * the shared reader dispatches unicast-group packets to. */
int netlink_nflog_group;

void netlink_update_binding(struct interface *ifp, union sockunion *proto,
			    union sockunion *nbma)
{
	nhrp_send_zebra_nbr(proto, nbma, ifp);
}

void netlink_log_indication(struct nlmsghdr *msg, struct zbuf *zb)
{
	struct nfgenmsg *nf;
	struct rtattr *rta;
	struct zbuf rtapl, pktpl;
	struct interface *ifp;
	struct nfulnl_msg_packet_hdr *pkthdr = NULL;
	uint32_t *in_ndx = NULL;

	nf = znl_pull(zb, sizeof(*nf));
	if (!nf)
		return;

	memset(&pktpl, 0, sizeof(pktpl));
	while ((rta = znl_rta_pull(zb, &rtapl)) != NULL) {
		switch (rta->rta_type) {
		case NFULA_PACKET_HDR:
			pkthdr = znl_pull(&rtapl, sizeof(*pkthdr));
			break;
		case NFULA_IFINDEX_INDEV:
			in_ndx = znl_pull(&rtapl, sizeof(*in_ndx));
			break;
		case NFULA_PAYLOAD:
			pktpl = rtapl;
			break;
			/* NFULA_HWHDR exists and is supposed to contain source
			 * hardware address. However, for ip_gre it seems to be
			 * the nexthop destination address if the packet matches
			 * route. */
		}
	}

	if (!pkthdr || !in_ndx || !zbuf_used(&pktpl))
		return;

	ifp = if_lookup_by_index(ntohl(*in_ndx), VRF_DEFAULT);
	if (!ifp)
		return;

	nhrp_peer_send_indication(ifp, htons(pkthdr->hw_protocol), &pktpl);
}

void netlink_set_nflog_group(int nlgroup)
{
	netlink_nflog_group = nlgroup;
	/* Rebind the shared NFLOG socket (owned by nhrp_multicast.c) so the
	 * redirect group is bound on the same portid==PID socket as the
	 * multicast OIL group — a second, separately-opened socket would bind
	 * fine but never receive packets from the kernel. */
	nhrp_nflog_resync();
}

int nhrp_neighbor_operation(ZAPI_CALLBACK_ARGS)
{
	union sockunion addr = {}, lladdr = {};
	struct interface *ifp;
	int state, ndm_state;
	struct nhrp_cache *c;
	struct zapi_neigh_ip api = {};

	zclient_neigh_ip_decode(zclient->ibuf, &api);

	if (api.ip_len != IPV4_MAX_BYTELEN && api.ip_len != 0)
		return 0;

	if (api.ip_in.ipa_type == AF_UNSPEC)
		return 0;
	sockunion_family(&addr) = api.ip_in.ipa_type;
	memcpy((uint8_t *)sockunion_get_addr(&addr), &api.ip_in.ip.addr,
	       family2addrsize(api.ip_in.ipa_type));

	sockunion_family(&lladdr) = api.ip_out.ipa_type;
	if (api.ip_out.ipa_type != AF_UNSPEC)
		memcpy((uint8_t *)sockunion_get_addr(&lladdr),
		       &api.ip_out.ip.addr,
		       family2addrsize(api.ip_out.ipa_type));

	ifp = if_lookup_by_index(api.index, vrf_id);
	ndm_state = api.ndm_state;

	if (!ifp)
		return 0;
	c = nhrp_cache_get(ifp, &addr, 0);
	if (!c)
		return 0;
	debugf(NHRP_DEBUG_KERNEL,
	       "Netlink: %s %pSU dev %s lladdr %pSU nud 0x%x cache used %u type %u",
	       (cmd == ZEBRA_NEIGH_GET)	    ? "who-has"
	       : (cmd == ZEBRA_NEIGH_ADDED) ? "new-neigh"
					    : "del-neigh",
	       &addr, ifp->name, &lladdr, ndm_state, c->used, c->cur.type);
	if (cmd == ZEBRA_NEIGH_GET && ndm_state != ZEBRA_NEIGH_STATE_INCOMPLETE) {
		if (c->cur.type >= NHRP_CACHE_CACHED) {
			nhrp_cache_set_used(c, 1);
			debugf(NHRP_DEBUG_KERNEL,
			       "Netlink: update binding for %pSU dev %s from c %pSU peer.vc.nbma %pSU to lladdr %pSU",
			       &addr, ifp->name, &c->cur.remote_nbma_natoa,
			       &c->cur.peer->vc->remote.nbma, &lladdr);

			if (lladdr.sa.sa_family == AF_UNSPEC)
				/* nothing from zebra, so use nhrp peer */
				lladdr = c->cur.peer->vc->remote.nbma;

			/* In case of shortcuts, nbma is given by lladdr, not
			 * vc->remote.nbma.
			 */
			netlink_update_binding(ifp, &addr, &lladdr);
		}
	} else {
		state = (cmd == ZEBRA_NEIGH_ADDED) ? ndm_state
						   : ZEBRA_NEIGH_STATE_FAILED;
		nhrp_cache_set_used(c, state == ZEBRA_NEIGH_STATE_REACHABLE);
	}
	return 0;
}
