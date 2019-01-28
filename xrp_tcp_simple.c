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

struct tcp4_pseudohdr {
	__be32		saddr;
	__be32		daddr;
	__u8		pad;
	__u8		protocol;
	__be16		len;
};

struct bpf_map_def SEC("maps") portmap = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 256,
};

SEC("xdp1")
//SEC("prog")
int xdp_prog1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct tcp4_pseudohdr  phdr;
	struct iphdr *iph, s_iph;
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
		//memset(&s_iph, 0, sizeof(s_iph));
		//memcpy(&s_iph, iph, sizeof(s_iph));
		nh_off += sizeof(*iph);
	} else
		return XDP_PASS;

	if(ipproto != IPPROTO_TCP)
		return XDP_PASS;
	else {
		tcph = data + nh_off;
		tcp_off = nh_off;
		if (tcph + 1 > data_end)
			return XDP_PASS;
		key = ntohs(tcph->dest);
		nh_off += sizeof(tcph);
	}

	value = bpf_map_lookup_elem(&portmap, &key);
	if(value) {
		char fmt[] = "found %d->%d\n";
		//void *ptr = data + tcp_off - sizeof(phdr);
		u32 temp = 0, temp2 = *value;
		bpf_trace_printk(fmt, sizeof(fmt),ntohs(key), ntohs(*value));
		//u16 new_csum  = 0;
		//phdr.saddr =  iph->saddr;
		//phdr.daddr =  iph->daddr;
		//phdr.pad = 0;
		//phdr.protocol =  iph->protocol;
		//phdr.len =  data_end - (void*)iph;
		//memcpy(ptr, &phdr, sizeof(phdr));
		//new_csum = bpf_csum_diff(NULL, 0, ptr, data_end - ptr, 0);
		temp =  (~(tcph->check)) + (~(tcph->dest)) + temp2;
		temp = ~((temp & 0x0FF) + (temp >> 16));
		if (tcph + 1 > data_end)
			return XDP_PASS;
		tcph->check = (u16) (temp & 0x0FF);
#if 0
		tcph->dest = (u16) *value;
		//memcpy(iph, &s_iph, sizeof(s_iph));
#endif
		return XDP_PASS;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
