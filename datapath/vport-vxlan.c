/*
 * Copyright (c) 2013 Nicira, Inc.
 * Copyright (c) 2013 Cisco Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/rculist.h>
#include <linux/udp.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/ip_tunnels.h>
#include <net/rtnetlink.h>
#include <net/route.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/vxlan.h>
#ifdef HAVE_UDP_TUNNEL_HANDLE_OFFLOADS
#include <net/udp_tunnel.h>
#endif

#include "datapath.h"
#include "vport.h"
#include "gso.h"

/**
 * struct vxlan_port - Keeps track of open UDP ports
 * @vs: vxlan_sock created for the port.
 * @name: vport name.
 */
struct vxlan_port {
	struct vxlan_sock *vs;
	char name[IFNAMSIZ];
};

static inline struct vxlan_port *vxlan_vport(const struct vport *vport)
{
	return vport_priv(vport);
}

static inline bool
vxlan_dst_port_eq(struct vxlan_port *vxlan_port, __be16 dst_port)
{
        if (vxlan_port->vs && inet_sport(vxlan_port->vs->sock->sk) == dst_port)
                return true;
        else
                return false;
}

/* Called with rcu_read_lock */
struct vxlan_sock *vxlan_find_sock(struct datapath *dp, __be16 dst_port)
{
        int i;
        struct vport *vport;
        struct vxlan_port *vxlan_port;

        for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
                hlist_for_each_entry_rcu(vport, &dp->ports[i], dp_hash_node) {
                        if (vport->ops->type == OVS_VPORT_TYPE_VXLAN) {
                                vxlan_port = vxlan_vport(vport);
                                if (vxlan_dst_port_eq(vxlan_port, dst_port))
                                        return vxlan_port->vs;
                        }
                }
        }
        return NULL;
}

/* Called with rcu_read_lock and BH disabled. */
static void vxlan_rcv(struct vxlan_sock *vs, struct sk_buff *skb, __be32 vx_vni)
{
	struct ovs_tunnel_info tun_info;
	struct vport *vport = vs->data;
	struct iphdr *iph;
	__be64 key;

	/* Save outer tunnel values */
	iph = ip_hdr(skb);
	key = cpu_to_be64(ntohl(vx_vni) >> 8);
	tun_info.tunnel.ivxlan_sepg = 0;
	tun_info.tunnel.ivxlan_flags = 0;
	ovs_flow_tun_info_init(&tun_info, iph,
			       udp_hdr(skb)->source, udp_hdr(skb)->dest,
			       key, TUNNEL_KEY, NULL, 0);

	ovs_vport_receive(vport, skb, &tun_info);
}

static int vxlan_get_options(const struct vport *vport, struct sk_buff *skb)
{
	struct vxlan_port *vxlan_port = vxlan_vport(vport);
	__be16 dst_port = inet_sport(vxlan_port->vs->sock->sk);

	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_DST_PORT, ntohs(dst_port)))
		return -EMSGSIZE;
	return 0;
}

static void vxlan_tnl_destroy(struct vport *vport)
{
	struct vxlan_port *vxlan_port = vxlan_vport(vport);

	vxlan_sock_release(vxlan_port->vs);

	ovs_vport_deferred_free(vport);
}

static struct vport *vxlan_tnl_create(const struct vport_parms *parms)
{
	struct net *net = ovs_dp_get_net(parms->dp);
	struct nlattr *options = parms->options;
	struct vxlan_port *vxlan_port;
	struct vxlan_sock *vs;
	struct vport *vport;
	struct nlattr *a;
	u16 dst_port;
	int err;

	if (!options) {
		err = -EINVAL;
		goto error;
	}
	a = nla_find_nested(options, OVS_TUNNEL_ATTR_DST_PORT);
	if (a && nla_len(a) == sizeof(u16)) {
		dst_port = nla_get_u16(a);
	} else {
		/* Require destination port from userspace. */
		err = -EINVAL;
		goto error;
	}

	vport = ovs_vport_alloc(sizeof(struct vxlan_port),
				&ovs_vxlan_vport_ops, parms);
	if (IS_ERR(vport))
		return vport;

	vxlan_port = vxlan_vport(vport);
	strncpy(vxlan_port->name, parms->name, IFNAMSIZ);

	vs = vxlan_sock_add(net, htons(dst_port), vxlan_rcv, vport, true, 0);
	if (IS_ERR(vs)) {
		ovs_vport_free(vport);
		return (void *)vs;
	}
	vxlan_port->vs = vs;

	return vport;

error:
	return ERR_PTR(err);
}

#ifndef HAVE_IPTUNNEL_HANDLE_OFFLOADS
static struct sk_buff *iptunnel_handle_offloads(struct sk_buff *skb,
					 bool csum_help,
					 int gso_type_mask)
{
	int err;

	if (likely(!skb->encapsulation)) {
		skb_reset_inner_headers(skb);
		skb->encapsulation = 1;
	}

	if (skb_is_gso(skb)) {
		err = skb_unclone(skb, GFP_ATOMIC);
		if (unlikely(err))
			goto error;
		skb_shinfo(skb)->gso_type |= gso_type_mask;
		return skb;
	}

	/* If packet is not gso and we are resolving any partial checksum,
	 * clear encapsulation flag. This allows setting CHECKSUM_PARTIAL
	 * on the outer header without confusing devices that implement
	 * NETIF_F_IP_CSUM with encapsulation.
	 */
	if (csum_help)
		skb->encapsulation = 0;

	if (skb->ip_summed == CHECKSUM_PARTIAL && csum_help) {
		err = skb_checksum_help(skb);
		if (unlikely(err))
			goto error;
	} else if (skb->ip_summed != CHECKSUM_PARTIAL)
		skb->ip_summed = CHECKSUM_NONE;

	return skb;
error:
	kfree_skb(skb);
	return ERR_PTR(err);
}
#endif

#ifndef HAVE_UDP_TUNNEL_HANDLE_OFFLOADS
static inline struct sk_buff *vxlan_handle_offloads(struct sk_buff *skb,
	                                                    bool udp_csum)
{
	int type = SKB_GSO_UDP_TUNNEL;
	return iptunnel_handle_offloads(skb, udp_csum, type);
}
#endif

#ifndef HAVE_UDP_V4_CHECK
static inline __sum16 udp_v4_check(int len, __be32 saddr,
                                   __be32 daddr, __wsum base)
{
	return csum_tcpudp_magic(saddr, daddr, len, IPPROTO_UDP, base);
}
#endif

#ifndef HAVE_UDP_SET_CSUM
static void udp_set_csum(bool nocheck, struct sk_buff *skb,
                  __be32 saddr, __be32 daddr, int len) __maybe_unused;

static void udp_set_csum(bool nocheck, struct sk_buff *skb,
                  __be32 saddr, __be32 daddr, int len)
{
        struct udphdr *uh = udp_hdr(skb);

        if (nocheck)
                uh->check = 0;
        else if (skb_is_gso(skb))
                uh->check = ~udp_v4_check(len, saddr, daddr, 0);
        else if (skb_dst(skb) && skb_dst(skb)->dev &&
                 (skb_dst(skb)->dev->features & NETIF_F_V4_CSUM)) {

                BUG_ON(skb->ip_summed == CHECKSUM_PARTIAL);

                skb->ip_summed = CHECKSUM_PARTIAL;
                skb->csum_start = skb_transport_header(skb) - skb->head;
                skb->csum_offset = offsetof(struct udphdr, check);
                uh->check = ~udp_v4_check(len, saddr, daddr, 0);
        } else {
                __wsum csum;

                BUG_ON(skb->ip_summed == CHECKSUM_PARTIAL);

                uh->check = 0;
                csum = skb_checksum(skb, 0, len, 0);
                uh->check = udp_v4_check(len, saddr, daddr, csum);
                if (uh->check == 0)
                        uh->check = CSUM_MANGLED_0;

                skb->ip_summed = CHECKSUM_UNNECESSARY;
        }
}

#endif

#define VXLAN_HLEN (sizeof(struct udphdr) + sizeof(struct vxlanhdr))

#define VXLAN_FLAGS 0x08000000  /* struct vxlanhdr.vx_flags required value. */

/* VXLAN protocol header */
struct vxlanhdr {
        __be32 vx_flags;
        __be32 vx_vni;
};

static void vxlan_sock_put(struct sk_buff *skb)
{
        sock_put(skb->sk);
}

/* On transmit, associate with the tunnel socket */
static void vxlan_set_owner(struct sock *sk, struct sk_buff *skb)
{
        skb_orphan(skb);
        sock_hold(sk);
        skb->sk = sk;
        skb->destructor = vxlan_sock_put;
}

static void vxlan_gso(struct sk_buff *skb)
{
        int udp_offset = skb_transport_offset(skb);
        struct udphdr *uh;

        uh = udp_hdr(skb);
        uh->len = htons(skb->len - udp_offset);

        /* csum segment if tunnel sets skb with csum. */
        if (unlikely(uh->check)) {
                struct iphdr *iph = ip_hdr(skb);

                uh->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
                                               skb->len - udp_offset,
                                               IPPROTO_UDP, 0);
                uh->check = csum_fold(skb_checksum(skb, udp_offset,
                                      skb->len - udp_offset, 0));

                if (uh->check == 0)
                        uh->check = CSUM_MANGLED_0;

        }
        skb->ip_summed = CHECKSUM_NONE;
}

static struct sk_buff *handle_offloads(struct sk_buff *skb)
{
        return ovs_iptunnel_handle_offloads(skb, false, vxlan_gso);
}

int vxlan_xmit_skb2(struct vxlan_sock *vs,
		   struct rtable *rt, struct sk_buff *skb,
		   __be32 src, __be32 dst, __u8 tos, __u8 ttl, __be16 df,
		   __be16 src_port, __be16 dst_port, __be32 vni)
{
	struct vxlanhdr *vxh;
	struct udphdr *uh;
	int min_headroom;
	int err;

	min_headroom = LL_RESERVED_SPACE(rt_dst(rt).dev) + rt_dst(rt).header_len
			+ VXLAN_HLEN + sizeof(struct iphdr)
			+ (vlan_tx_tag_present(skb) ? VLAN_HLEN : 0);

	/* Need space for new headers (invalidates iph ptr) */
	err = skb_cow_head(skb, min_headroom);
	if (unlikely(err)) {
		kfree_skb(skb);
		return err;
	}

	if (vlan_tx_tag_present(skb)) {
		if (unlikely(!vlan_insert_tag_set_proto(skb,
							skb->vlan_proto,
							vlan_tx_tag_get(skb))))
			return -ENOMEM;

		vlan_set_tci(skb, 0);
	}

	skb_reset_inner_headers(skb);

	vxh = (struct vxlanhdr *) __skb_push(skb, sizeof(*vxh));
	vxh->vx_flags = htonl(VXLAN_FLAGS);
	vxh->vx_vni = vni;

	__skb_push(skb, sizeof(*uh));
	skb_reset_transport_header(skb);
	uh = udp_hdr(skb);

	uh->dest = dst_port;
	uh->source = src_port;

	uh->len = htons(skb->len);
	uh->check = 0;

	vxlan_set_owner(vs->sock->sk, skb);

	skb = handle_offloads(skb);
	if (IS_ERR(skb))
		return PTR_ERR(skb);

	return iptunnel_xmit(vs->sock->sk, rt, skb, src, dst, IPPROTO_UDP,
			     tos, ttl, df, false);
}

static int vxlan_tnl_send(struct vport *vport, struct sk_buff *skb)
{
	struct ovs_key_ipv4_tunnel *tun_key;
	struct net *net = ovs_dp_get_net(vport->dp);
	struct vxlan_port *vxlan_port = vxlan_vport(vport);
	__be16 dst_port = inet_sport(vxlan_port->vs->sock->sk);
	struct rtable *rt;
	__be16 src_port;
	__be32 saddr;
	__be16 df;
	int err;

	if (unlikely(!OVS_CB(skb)->egress_tun_info)) {
		err = -EINVAL;
		goto error;
	}

	tun_key = &OVS_CB(skb)->egress_tun_info->tunnel;

	/* Route lookup */
	saddr = tun_key->ipv4_src;
	rt = find_route(ovs_dp_get_net(vport->dp),
			&saddr, tun_key->ipv4_dst,
			IPPROTO_UDP, tun_key->ipv4_tos,
			skb->mark);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		goto error;
	}

	df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ? htons(IP_DF) : 0;
	skb->ignore_df = 1;

	src_port = udp_flow_src_port(net, skb, 0, 0, true);

	err = vxlan_xmit_skb2(vxlan_port->vs, rt, skb,
			     saddr, tun_key->ipv4_dst,
			     tun_key->ipv4_tos,
			     tun_key->ipv4_ttl, df,
			     src_port, dst_port,
			     htonl(be64_to_cpu(tun_key->tun_id) << 8));
	if (err < 0)
		ip_rt_put(rt);
	return err;
error:
	kfree_skb(skb);
	return err;
}

static int vxlan_get_egress_tun_info(struct vport *vport, struct sk_buff *skb,
				     struct ovs_tunnel_info *egress_tun_info)
{
	struct net *net = ovs_dp_get_net(vport->dp);
	struct vxlan_port *vxlan_port = vxlan_vport(vport);
	__be16 dst_port = inet_sport(vxlan_port->vs->sock->sk);
	__be16 src_port;

	src_port = udp_flow_src_port(net, skb, 0, 0, true);

	return ovs_tunnel_get_egress_info(egress_tun_info, net,
					  OVS_CB(skb)->egress_tun_info,
					  IPPROTO_UDP, skb->mark,
					  src_port, dst_port);
}

static const char *vxlan_get_name(const struct vport *vport)
{
	struct vxlan_port *vxlan_port = vxlan_vport(vport);
	return vxlan_port->name;
}

const struct vport_ops ovs_vxlan_vport_ops = {
	.type			= OVS_VPORT_TYPE_VXLAN,
	.create			= vxlan_tnl_create,
	.destroy		= vxlan_tnl_destroy,
	.get_name		= vxlan_get_name,
	.get_options		= vxlan_get_options,
	.send			= vxlan_tnl_send,
	.get_egress_tun_info	= vxlan_get_egress_tun_info,
};
