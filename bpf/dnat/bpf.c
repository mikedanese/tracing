#include <linux/netfilter.h>
#include <linux/skbuff.h>

#include <uapi/linux/ptrace.h>

#include <bcc/proto.h>



struct trace_data {
	u64 ts_us;
};
BPF_PERF_OUTPUT(dnat_events);


BPF_HASH(skb_tbl, u32, struct sk_buff *);
BPF_HASH(nf_hook_state_tbl, u32, struct nf_hook_state *);

int trace_undnat_entry(struct pt_regs *ctx, void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state) {
	return 0;
};

int trace_undnat_return(struct pt_regs *ctx) {
	struct trace_data d;
	d.ts_us = bpf_ktime_get_ns() / 1000;
	dnat_events.perf_submit(ctx, &d, sizeof(d));
	return 0;
};
