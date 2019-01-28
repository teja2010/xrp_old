// SPDX-License-Identifier: GPL-2.0

#define KBUILD_MODNAME "xrp_tcp_simple"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") portmap = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 256,
};

SEC("xdp1")
//SEC("prog")
int xdp_prog1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct tcphdr *tcph;
	long *value;
	u16 h_proto;
	u64 nh_off, tcp_off;
	u32 ipproto, key;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_PASS;

	h_proto = eth->h_proto;

	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return XDP_PASS;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return XDP_PASS;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if (h_proto == htons(ETH_P_IP)) {
		iph = data + nh_off;
		if (iph + 1 > data_end)
			return XDP_PASS;
		ipproto = iph->protocol;
		nh_off += sizeof(*iph);
	} else
		return XDP_PASS;

	if(ipproto != IPPROTO_TCP)
		return XDP_PASS;
	else {
		tcph = data + nh_off;
		tcp_off = nh_off;
		if (tcph + 2 > data_end)
			return XDP_PASS;
		key = tcph->dest;
		nh_off += sizeof(tcph);
	}

	value = bpf_map_lookup_elem(&portmap, &key);
	if(value) {
		char fmt1[] = "found %d->%d, csum %lx\n";
		char fmt2[] = "one %lx, two %x, temp %x\n";
		u32 temp = 0, temp2 = (u32)*value;
		bpf_trace_printk(fmt1, sizeof(fmt1),ntohs(key), ntohs(*value),
				 tcph->check);
		temp =  (((u32)(~(tcph->check)))&0x0FFFF) +
			(((u32)(~(tcph->dest)))&0x0FFFF) + temp2;
		bpf_trace_printk(fmt2, sizeof(fmt2), (((u32)(~(tcph->check)))&0x0FFFF),
				(((u32)(~(tcph->dest)))&0x0FFFF), temp);
		
		temp = ~((temp & 0x0FFFF) + (temp >> 16));
		//if (tcph + 2 > data_end)
		//	return XDP_PASS;
		tcph->check = (u16) (temp & 0x0FFFF);
		tcph->dest =  *value;
		return XDP_PASS;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
