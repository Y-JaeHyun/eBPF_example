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
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	const char fmt_str[] = "tcp_v4_connect(ret)\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
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

