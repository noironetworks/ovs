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
#include <net/ivxlan.h>
#include <net/vxlan.h>

#include "datapath.h"
#include "vport.h"

struct ivxlanhdr_word1 {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u16 reserved_flags:3,
              instance_id_present:1,
              map_version_present:1,
              solicit_echo_nonce:1,
              locator_status_bits_present:1,
              nonce_present:1,

              dre_or_mcast_bits:3,
              dst_epg_policy_applied:1,
              src_epg_policy_applied:1,
              forward_exception:1,
              dont_learn_addr_to_tep:1,
              load_balancing_enabled:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
        __u16 nonce_present:1,
              locator_status_bits_present:1,
              solicit_echo_nonce:1,
              map_version_present:1,
              instance_id_present:1,
              reserved_flags:3,

              load_balancing_enabled:1,
              dont_learn_addr_to_tep:1,
              forward_exception:1,
              src_epg_policy_applied:1,
              dst_epg_policy_applied:1,
              dre_or_mcast_bits:3;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
        __be16 src_group;
};

struct ivxlanhdr {
        union {
                struct ivxlanhdr_word1 word1;
                __be32 vx_flags;
        } u1;
        __be32 vx_vni;
};

#define IVXLAN_HLEN (sizeof(struct udphdr) + sizeof(struct ivxlanhdr))

#define IVXLAN_FLAGS 0x08000000  /* struct ivxlanhdr.vx_flags required value. */

/**
 * struct ivxlan_port - Keeps track of open UDP ports
 * @vs: vxlan_sock created for the port.
 * @name: vport name.
 */
struct ivxlan_port {
	struct vxlan_sock *vs;
        __be16 ivxlan_sepg;
	char name[IFNAMSIZ];
};

static inline struct ivxlan_port *ivxlan_vport(const struct vport *vport)
{
	return vport_priv(vport);
}


/* Called with rcu_read_lock and BH disabled from vxlan_udp_encap_recv. */
static struct vxlanhdr *ivxlan_udp_encap_parse_hdr(struct sock *sk, struct sk_buff *skb, int *retval)
{
        struct ivxlanhdr *ivxh;
	struct ovs_tunnel_info tun_info;
	struct vxlan_sock *vs;
	struct iphdr *iph;
	struct vport *vport;
	__be64 key;

	ivxh = (struct ivxlanhdr *)(udp_hdr(skb) + 1);
        if (likely(ivxh->u1.word1.nonce_present)) {
            tun_info.tunnel.ivxlan_sepg = ivxh->u1.word1.src_group;
            tun_info.tunnel.ivxlan_spa = ivxh->u1.word1.src_epg_policy_applied;
	} else if (ivxh->u1.vx_flags != htonl(IVXLAN_FLAGS) ||
                   (ivxh->vx_vni & htonl(0xff))) {
            pr_warn("invalid vxlan flags=%#x vni=%#x\n",
                    ntohl(ivxh->u1.vx_flags), ntohl(ivxh->vx_vni));
	    *retval = VXLAN_PARSE_ERR;
            return NULL;
        }
            
	*retval = VXLAN_PARSE_CONSUMED;
	vs = rcu_dereference_sk_user_data(sk);
	if (!vs || iptunnel_pull_header(skb, IVXLAN_HLEN, htons(ETH_P_TEB))) {
                kfree_skb(skb);
		return NULL;
	}

	vport = vs->data;
	iph = ip_hdr(skb);
	key = cpu_to_be64(ntohl(ivxh->vx_vni) >> 8);
        /* MUST not zero tun_info */
        ovs_flow_tun_info_init(&tun_info, iph, key, TUNNEL_KEY, NULL, 0);    
	ovs_vport_receive(vport, skb, &tun_info);

	return NULL;
}

static void ivxlan_construct_hdr(struct sk_buff *skb, __be32 vni)
{
	struct ivxlanhdr *ivxh = (struct ivxlanhdr *) __skb_push(skb, sizeof(*ivxh));
        struct ovs_key_ipv4_tunnel *tun_key = &OVS_CB(skb)->egress_tun_info->tunnel;
	ivxh->u1.vx_flags = htonl(IVXLAN_FLAGS);
	ivxh->vx_vni = vni;
	ivxh->u1.word1.nonce_present = 1;
	ivxh->u1.word1.src_group = tun_key->ivxlan_sepg;
	ivxh->u1.word1.src_epg_policy_applied = tun_key->ivxlan_spa;
}

/* Called with rcu_read_lock and BH disabled. */
static void ivxlan_rcv(struct vxlan_sock *vs, struct sk_buff *skb, __be32 vx_vni)
{
	BUG();
}

static int ivxlan_get_options(const struct vport *vport, struct sk_buff *skb)
{
	struct ivxlan_port *ivxlan_port = ivxlan_vport(vport);
	__be16 dst_port = inet_sport(ivxlan_port->vs->sock->sk);

	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_DST_PORT, ntohs(dst_port)))
		return -EMSGSIZE;
	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_EPG, 
            ntohs(ivxlan_port->ivxlan_sepg)))
		return -EMSGSIZE;
	return 0;
}

static void ivxlan_tnl_destroy(struct vport *vport)
{
	struct ivxlan_port *ivxlan_port = ivxlan_vport(vport);

	vxlan_sock_release(ivxlan_port->vs);

	ovs_vport_deferred_free(vport);
}

static struct vport *ivxlan_tnl_create(const struct vport_parms *parms)
{
	struct net *net = ovs_dp_get_net(parms->dp);
	struct nlattr *options = parms->options;
	struct ivxlan_port *ivxlan_port;
	struct vxlan_sock *vs;
	struct vxlan_ext vext;
	struct vport *vport;
	struct nlattr *a;
	u16 dst_port, epg;
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

        a = nla_find_nested(options, OVS_TUNNEL_ATTR_EPG);
        if (a && nla_len(a) == sizeof(u16)) {
                epg = nla_get_u16(a);
        } else {
                epg = 0;
        }

	vport = ovs_vport_alloc(sizeof(struct ivxlan_port),
				&ovs_ivxlan_vport_ops, parms);
	if (IS_ERR(vport))
		return vport;

	ivxlan_port = ivxlan_vport(vport);
	strncpy(ivxlan_port->name, parms->name, IFNAMSIZ);

        ivxlan_port->ivxlan_sepg = htons(epg);

	vs = vxlan_sock_add(net, htons(dst_port), ivxlan_rcv, vport, true, false);
	if (IS_ERR(vs)) {
		ovs_vport_free(vport);
		return (void *)vs;
	}
	vext.parse = ivxlan_udp_encap_parse_hdr;
	vext.construct = ivxlan_construct_hdr;
	vxlan_register_extensions(vs, &vext);
	ivxlan_port->vs = vs;

	return vport;

error:
	return ERR_PTR(err);
}

static int ivxlan_tnl_send(struct vport *vport, struct sk_buff *skb)
{
        struct ovs_key_ipv4_tunnel *tun_key;
	struct net *net = ovs_dp_get_net(vport->dp);
	struct ivxlan_port *ivxlan_port = ivxlan_vport(vport);
	__be16 dst_port = inet_sport(ivxlan_port->vs->sock->sk);
	struct rtable *rt;
	__be16 src_port;
	__be32 saddr;
	__be16 df;
	int port_min;
	int port_max;
	int err;

	if (unlikely(!OVS_CB(skb)->egress_tun_info)) {
		err = -EINVAL;
		goto error;
	}

        tun_key = &OVS_CB(skb)->egress_tun_info->tunnel;

	/* Route lookup */
	saddr = tun_key->ipv4_src;
	rt = find_route(ovs_dp_get_net(vport->dp),
			&saddr,
			tun_key->ipv4_dst,
			IPPROTO_UDP,
			tun_key->ipv4_tos,
			skb->mark);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		goto error;
	}

	df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ? htons(IP_DF) : 0;

	skb->local_df = 1;

	inet_get_local_port_range(net, &port_min, &port_max);
	src_port = vxlan_src_port(port_min, port_max, skb);
	if (tun_key->ivxlan_sepg == 0)
	    tun_key->ivxlan_sepg = ivxlan_port->ivxlan_sepg;
	err = vxlan_xmit_skb(ivxlan_port->vs, rt, skb,
			     saddr, tun_key->ipv4_dst,
			     tun_key->ipv4_tos,
			     tun_key->ipv4_ttl, df,
			     src_port, dst_port,
			     htonl(be64_to_cpu(tun_key->tun_id) << 8));
	if (err < 0)
		ip_rt_put(rt);
error:
	return err;
}

static const char *ivxlan_get_name(const struct vport *vport)
{
	struct ivxlan_port *ivxlan_port = ivxlan_vport(vport);
	return ivxlan_port->name;
}

const struct vport_ops ovs_ivxlan_vport_ops = {
	.type		= OVS_VPORT_TYPE_IVXLAN,
	.create		= ivxlan_tnl_create,
	.destroy	= ivxlan_tnl_destroy,
	.get_name	= ivxlan_get_name,
	.get_options	= ivxlan_get_options,
	.send		= ivxlan_tnl_send,
};
