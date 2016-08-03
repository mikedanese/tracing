#include <linux/netfilter.h>
#include <linux/skbuff.h>

#include <uapi/linux/ptrace.h>

#include <bcc/proto.h>


int kprobe__iptables_nat_ipv4_in(struct pt_regs *ctx, void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state) {
	return 0;
};
int kprobe__iptable_nat_ipv4_local_fn(struct pt_regs *ctx, void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state) {
	return 0;
};
