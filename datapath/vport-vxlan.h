#ifndef VPORT_VXLAN_H
#define VPORT_VXLAN_H 1

#include <linux/kernel.h>
#include <linux/types.h>

int ovs_vxlan_tnl_init(void);
void ovs_vxlan_tnl_exit(void);

struct ovs_vxlan_opts {
	__u32 gbp;
};

#endif
