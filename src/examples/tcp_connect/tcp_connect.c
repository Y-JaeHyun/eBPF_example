// +build ignore

#define __TARGET_ARCH_x86
#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "tcp_connect.h"

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

/**
 * The sample submitted to userspace over a ring buffer.
 * Emit struct event's type info into the ELF's BTF so bpf2go
 * can generate a Go type from it.
 */
struct event {
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
	u32 srtt;
	/*
	u32 rttvar_us;
	u32 unused1;
	u64 unused2;*/
};

struct event *unused_event_t  __attribute__((unused));
struct pid_comm_t *unused_pid_comm_t  __attribute__((unused));
struct ipv4_tuple_t *unused_ipv4_tuple_t  __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(void *));
	__uint(max_entries, 1024);
} connectsock_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(void *));
	__uint(max_entries, 1024);
} sendmsg_ipv4 SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct ipv4_tuple_t));
	__uint(value_size, sizeof(struct pid_comm_t));
	__uint(max_entries, 1024);
} send_check_ipv4 SEC(".maps");



struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct ipv4_tuple_t));
	__uint(value_size, sizeof(struct pid_comm_t));
	__uint(max_entries, 1024);
} tuplepid_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct ipv6_tuple_t));
	__uint(value_size, sizeof(struct pid_comm_t));
	__uint(max_entries, 1024);
} tuplepid_ipv6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct pid_comm_t));
	__uint(value_size, sizeof(struct tcp_ipv4_event_t));
	__uint(max_entries, 1024);
} tcp_event_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1024);
} tcp_event_ipv6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
//	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, 0);
	__uint(value_size, sizeof(struct event));
	__uint(max_entries, 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
//	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, 0);
	__uint(value_size, sizeof(struct event));
	__uint(max_entries, 1024);
} events2 SEC(".maps");


SEC("kprobe/tcp_close")
int BPF_KPROBE(tcp_close, struct sock *sk) {
	bpf_printk("tcp_close\n");
	short unsigned int family = 0;

	bpf_probe_read_kernel(&family, sizeof(family), &(sk->__sk_common.skc_family));

	if (family != AF_INET) {
		return 0;
	}

	struct event tcp_info;
	struct tcp_sock *ts = (struct tcp_sock*)sk;

	bpf_probe_read_kernel(&tcp_info.saddr, sizeof(tcp_info.saddr), &(sk->__sk_common.skc_rcv_saddr));
	bpf_probe_read_kernel(&tcp_info.daddr, sizeof(tcp_info.daddr), &(sk->__sk_common.skc_daddr));
	bpf_probe_read_kernel(&tcp_info.sport, sizeof(tcp_info.sport), &(sk->__sk_common.skc_num));
	bpf_probe_read_kernel(&tcp_info.dport, sizeof(tcp_info.dport), &(sk->__sk_common.skc_dport));
	tcp_info.dport = bpf_ntohs(tcp_info.dport);

	bpf_probe_read_kernel(&tcp_info.srtt, sizeof(tcp_info.srtt), &ts->srtt_us);
//	bpf_probe_read_kernel(&tcp_info.rttvar_us, sizeof(tcp_info.rttvar_us), &ts->rttvar_us);

	tcp_info.srtt = (tcp_info.srtt >> 3) / 1000;
//	tcp_info.rttvar_us /= 1000;

	bpf_map_push_elem(&events, &tcp_info, 0);

	return 0;
}

SEC("kprobe/tcp_set_state")
int kprobe__tcp_set_state(struct pt_regs* ctx) {
	bpf_printk("tcp_set_state\n");
	struct event tcp_info = {0, };
	int state = (int) PT_REGS_PARM2(ctx);
	tcp_info.srtt = state;

	bpf_map_push_elem(&events2, &tcp_info, 0);
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs*ctx) {
	bpf_printk("tcp_sendmsg\n");
	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&sendmsg_ipv4, &pid, &sk, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe__tcp_sendmsg(struct pt_regs*ctx) {
	bpf_printk("tcp_sendmsg(ret)\n");
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	u64 zero = 0;

	skpp = bpf_map_lookup_elem(&sendmsg_ipv4, &pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	struct sock *sk = *skpp;
	sk = NULL;

	short unsigned int family = 0;

	bpf_probe_read_kernel(&family, sizeof(family), &(sk->__sk_common.skc_family));

	bpf_map_delete_elem(&sendmsg_ipv4, &pid);
	if (ret != 0) {
		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	//short unsigned int family = 0;

	//bpf_probe_read_kernel(&family, sizeof(family), &(sk->__sk_common.skc_family));

	struct tcp_sock *ts = (struct tcp_sock*)sk;

	struct ipv4_tuple_t tcp_info = { };

	bpf_probe_read_kernel(&tcp_info.saddr, sizeof(tcp_info.saddr), &(sk->__sk_common.skc_rcv_saddr));
	bpf_probe_read_kernel(&tcp_info.daddr, sizeof(tcp_info.daddr), &(sk->__sk_common.skc_daddr));
	bpf_probe_read_kernel(&tcp_info.sport, sizeof(tcp_info.sport), &(sk->__sk_common.skc_num));
	bpf_probe_read_kernel(&tcp_info.dport, sizeof(tcp_info.dport), &(sk->__sk_common.skc_dport));
	tcp_info.dport = bpf_ntohs(tcp_info.dport);

	bpf_probe_read_kernel(&tcp_info.netns, sizeof(tcp_info.netns), &ts->srtt_us);
//	bpf_probe_read_kernel(&tcp_info.rttvar_us, sizeof(tcp_info.rttvar_us), &ts->rttvar_us);

	tcp_info.netns= (tcp_info.netns>> 3) / 1000;
//	tcp_info.rttvar_us /= 1000;



	struct pid_comm_t p = { .pid = pid };
	bpf_get_current_comm(p.comm, sizeof(p.comm));
	int32_t bytes_sent = PT_REGS_RC(ctx);

	bpf_map_update_elem(&send_check_ipv4, &tcp_info, &p, BPF_ANY);
	return 0;



}

SEC("kprobe/tcp_sendpage")
int kprobe__tcp_sendpage(struct pt_regs *ctx) {
	bpf_printk("tcp_sendpageyy\n");
	struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
	int32_t bytes_sent = (int32_t)PT_REGS_PARM4(ctx);

	return 0;

}



SEC("kprobe/inet_csk_accept")
int kprobe__inet_csk_accept(struct pt_regs* ctx) {
	bpf_printk("inet_csk_accept\n");
	struct event tcp_info = {0, };
	bpf_map_push_elem(&events2, &tcp_info, 0);
	return 0;
}
SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs* ctx) {
	bpf_printk("inet_csk_accept(ret)\n");
	struct sock* sk = (struct sock*)PT_REGS_RC(ctx);
	struct event tcp_info = {0, };
	bpf_map_push_elem(&events2, &tcp_info, 0);
	/*
	if (!sk) {
		return 0;
	}
	struct event tcp_info;
	struct tcp_sock *ts = (struct tcp_sock*)sk;

	bpf_probe_read_kernel(&tcp_info.saddr, sizeof(tcp_info.saddr), &(sk->__sk_common.skc_rcv_saddr));
	bpf_probe_read_kernel(&tcp_info.daddr, sizeof(tcp_info.daddr), &(sk->__sk_common.skc_daddr));
	bpf_probe_read_kernel(&tcp_info.sport, sizeof(tcp_info.sport), &(sk->__sk_common.skc_num));
	bpf_probe_read_kernel(&tcp_info.dport, sizeof(tcp_info.dport), &(sk->__sk_common.skc_dport));
	tcp_info.dport = bpf_ntohs(tcp_info.dport);

	bpf_probe_read_kernel(&tcp_info.srtt, sizeof(tcp_info.srtt), &ts->srtt_us);
//	bpf_probe_read_kernel(&tcp_info.rttvar_us, sizeof(tcp_info.rttvar_us), &ts->rttvar_us);

	tcp_info.srtt = (tcp_info.srtt >> 3) / 1000;
//	tcp_info.rttvar_us /= 1000;

	bpf_map_push_elem(&events2, &tcp_info, 0);
	*/
	return 0;
}




SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	bpf_printk("tcp_v4_connect\n");
	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&connectsock_ipv4, &pid, &sk, BPF_ANY);

	return 0;
}



SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	bpf_printk("tcp_v4_connect (ret)\n");
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	u64 zero = 0;
	struct tcptracer_status_t *status;

	skpp = bpf_map_lookup_elem(&connectsock_ipv4, &pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	struct sock *sk = *skpp;

	bpf_map_delete_elem(&connectsock_ipv4, &pid);
	if (ret != 0) {

		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	short unsigned int family = 0;

	bpf_probe_read_kernel(&family, sizeof(family), &(sk->__sk_common.skc_family));

	struct tcp_sock *ts = (struct tcp_sock*)sk;

	struct ipv4_tuple_t tcp_info = { };

	bpf_probe_read_kernel(&tcp_info.saddr, sizeof(tcp_info.saddr), &(sk->__sk_common.skc_rcv_saddr));
	bpf_probe_read_kernel(&tcp_info.daddr, sizeof(tcp_info.daddr), &(sk->__sk_common.skc_daddr));
	bpf_probe_read_kernel(&tcp_info.sport, sizeof(tcp_info.sport), &(sk->__sk_common.skc_num));
	bpf_probe_read_kernel(&tcp_info.dport, sizeof(tcp_info.dport), &(sk->__sk_common.skc_dport));
	tcp_info.dport = bpf_ntohs(tcp_info.dport);

	bpf_probe_read_kernel(&tcp_info.netns, sizeof(tcp_info.netns), &ts->srtt_us);
//	bpf_probe_read_kernel(&tcp_info.rttvar_us, sizeof(tcp_info.rttvar_us), &ts->rttvar_us);

	tcp_info.netns= (tcp_info.netns>> 3) / 1000;
//	tcp_info.rttvar_us /= 1000;



	struct pid_comm_t p = { .pid = pid };
	bpf_get_current_comm(p.comm, sizeof(p.comm));

	bpf_map_update_elem(&tuplepid_ipv4, &tcp_info, &p, BPF_ANY);
	return 0;
}

//tcp_recvmsg 대체
SEC("kprobe/tcp_cleanup_rbuf")
int kprobe__tcp__cleanup_rbpf(struct pt_regs *ctx) {
	bpf_printk("tcp_cleanup_rbuf\n");
	return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int kprobe__tcp_retransmit_skb(struct pt_regs *ctx) {
	bpf_printk("tcp_retransmit_skb\n");
	return 0;
	
}

