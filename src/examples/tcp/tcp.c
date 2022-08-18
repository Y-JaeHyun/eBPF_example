// +build ignore

#define __TARGET_ARCH_x86
#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"
//#include "tcp_connect.h"

#define AF_INET 2
#define AF_INET6 10

enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING,	/* Now a valid state */
	TCP_NEW_SYN_RECV,

	TCP_MAX_STATES	/* Leave at the end! */
};

char __license[] SEC("license") = "GPL";

struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
	int sk_sndbuf;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct tcp_sock {
	u32 aaaa;
	u32 srtt_us;
	u32 mdev_us;     /* medium deviation			*/
	u32 mdev_max_us; /* maximal mdev for the last rtt period	*/
	u32 rttvar_us;   /* smoothed mdev_max			*/
	u32 rtt_seq;     /* sequence number to update rttvar	*/
} __attribute__((preserve_access_index));

/////////////////////////////////////////////////////////

struct key {
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
	u32 pid;
};

struct value{
	u32 srtt;
	u32 rttvar;
	u32 status;
};

struct key *unused_key_t  __attribute__((unused));
struct value *unused_value_t  __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(void *));
	__uint(max_entries, 1024);
} connectsock_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct key));
	__uint(value_size, sizeof(struct value));
	__uint(max_entries, 1024);
} matrix_map SEC(".maps");



///
SEC("kprobe/tcp_close")
int kprobe__tcp_close(struct pt_regs *ctx) {
	const char fmt_str[] = "tcp_close\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	return 0;
}

SEC("kprobe/tcp_set_state")
int kprobe__tcp_set_state(struct pt_regs* ctx) {
	const char fmt_str[] = "tcp_set_state\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs*ctx) {
	const char fmt_str[] = "tcp_sendmsg\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe__tcp_sendmsg(struct pt_regs*ctx) {
	const char fmt_str[] = "tcp_sendmsg(ret)\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	return 0;
}
SEC("kprobe/tcp_sendpage")
int kprobe__tcp_sendpage(struct pt_regs *ctx) {
	const char fmt_str[] = "tcp_sendpage\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	return 0;

}

SEC("kprobe/inet_csk_accept")
int kprobe__inet_csk_accept(struct pt_regs* ctx) {
	const char fmt_str[] = "inet_csk_accept\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	return 0;
}

SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs* ctx) {
	const char fmt_str[] = "inet_csk_accept(ret)\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	const char fmt_str[] = "tcp_v4_connect\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));

	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&connectsock_ipv4, &pid, &sk, BPF_ANY);

	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	const char fmt_str[] = "tcp_v4_connect(ret)\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&connectsock_ipv4, &pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	struct sock *sk = *skpp;
	bpf_map_delete_elem(&connectsock_ipv4, &pid);
	int ret = PT_REGS_RC(ctx);
	if (ret != 0) {

		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	short unsigned int family = 0;

	bpf_probe_read_kernel(&family, sizeof(family), &(sk->__sk_common.skc_family));

	struct key k;
	struct value v;
	struct tcp_sock *ts = (struct tcp_sock*)sk;

	bpf_probe_read_kernel(&k.saddr, sizeof(k.saddr), &(sk->__sk_common.skc_rcv_saddr));
	bpf_probe_read_kernel(&k.daddr, sizeof(k.daddr), &(sk->__sk_common.skc_daddr));
	bpf_probe_read_kernel(&k.sport, sizeof(k.sport), &(sk->__sk_common.skc_num));
	bpf_probe_read_kernel(&k.dport, sizeof(k.dport), &(sk->__sk_common.skc_dport));
	k.dport = bpf_ntohs(k.dport);

	bpf_probe_read_kernel(&v.srtt, sizeof(v.srtt), &ts->srtt_us);
	v.srtt = 0;
	v.rttvar = 0;
	v.status = 2;

	bpf_map_update_elem(&matrix_map, &k, &v, BPF_ANY);

	return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe__tcp__cleanup_rbpf(struct pt_regs *ctx) {
	const char fmt_str[] = "tcp_cleanup_rbuf\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	return 0;
}
SEC("kprobe/tcp_retransmit_skb")
int kprobe__tcp_retransmit_skb(struct pt_regs *ctx) {
	const char fmt_str[] = "tcp_retransmit_sk\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe__tcp__recvmsg(struct pt_regs *ctx) {
	const char fmt_str[] = "tcp_recvmsg\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	return 0;
}

