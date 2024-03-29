// +build ignore

#define __TARGET_ARCH_x86
#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"

#define AF_INET 2

char __license[] SEC("license") = "Dual MIT/GPL";

/**
 * For CO-RE relocatable eBPF programs, __attribute__((preserve_access_index))
 * preserves the offset of the specified fields in the original kernel struct.
 * So here we don't need to include "vmlinux.h". Instead we only need to define
 * the kernel struct and their fields the eBPF program actually requires.
 *
 * Also note that BTF-enabled programs like fentry, fexit, fmod_ret, tp_btf,
 * lsm, etc. declared using the BPF_PROG macro can read kernel memory without
 * needing to call bpf_probe_read*().
 */

/**
 * struct sock_common is the minimal network layer representation of sockets.
 * This is a simplified copy of the kernel's struct sock_common.
 * This copy contains only the fields needed for this example to
 * fetch the source and destination port numbers and IP addresses.
 */
struct sock_common {
	union {
		struct {
			// skc_daddr is destination IP address
			__be32 skc_daddr;
			// skc_rcv_saddr is the source IP address
			__be32 skc_rcv_saddr;
		};
	};
	union {
		struct {
			// skc_dport is the destination TCP/UDP port
			__be16 skc_dport;
			// skc_num is the source TCP/UDP port
			__u16 skc_num;
		};
	};
	// skc_family is the network address family (2 for IPV4)
	short unsigned int skc_family;
} __attribute__((preserve_access_index));

/**
 * struct sock is the network layer representation of sockets.
 * This is a simplified copy of the kernel's struct sock.
 * This copy is needed only to access struct sock_common.
 */
struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

/**
 * struct tcp_sock is the Linux representation of a TCP socket.
 * This is a simplified copy of the kernel's struct tcp_sock.
 * For this example we only need srtt_us to read the smoothed RTT.
 */
struct tcp_sock {
	u32 srtt_us;
	u32 mdev_us;     /* medium deviation			*/
	u32 mdev_max_us; /* maximal mdev for the last rtt period	*/
	u32 rttvar_us;   /* smoothed mdev_max			*/
	u32 rtt_seq;     /* sequence number to update rttvar	*/
} __attribute__((preserve_access_index));
/*
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");
*/

/**
 * The sample submitted to userspace over a ring buffer.
 * Emit struct event's type info into the ELF's BTF so bpf2go
 * can generate a Go type from it.
 */
struct key {
	u32 unused1;
	u64 unused2;
};
struct value {
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
	u32 srtt;
	u32 rttvar_us;
};

struct key *unused_key __attribute__((unused));
struct value *unused_value __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);

	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct value));
//	__uint(key_size, sizeof(struct key));
//	__uint(value_size, sizeof(struct value));
	__uint(max_entries, 1024);
} events SEC(".maps");

/*
struct bpf_map_def SEC("maps/tcp_close") events = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(struct key),
	.value_size = sizeof(struct value),
	.max_entries = 1024,
};
*/

SEC("kprobe/tcp_close")
int BPF_KPROBE(tcp_close, struct sock *sk) {
	short unsigned int family = 0;

	bpf_probe_read_kernel(&family, sizeof(family), &(sk->__sk_common.skc_family));

	if (family != AF_INET) {
		return 0;
	}

	struct key k;
	struct value v;
	struct tcp_sock *ts = (struct tcp_sock*)sk;

	u32 index = 0;

	bpf_probe_read_kernel(&v.saddr, sizeof(v.saddr), &(sk->__sk_common.skc_rcv_saddr));
	bpf_probe_read_kernel(&v.daddr, sizeof(v.daddr), &(sk->__sk_common.skc_daddr));
	bpf_probe_read_kernel(&v.sport, sizeof(v.sport), &(sk->__sk_common.skc_num));
	bpf_probe_read_kernel(&v.dport, sizeof(v.dport), &(sk->__sk_common.skc_dport));
	v.dport = bpf_ntohs(v.dport);

	bpf_probe_read_kernel(&v.srtt, sizeof(v.srtt), &ts->srtt_us);
	bpf_probe_read_kernel(&v.rttvar_us, sizeof(v.rttvar_us), &ts->rttvar_us);

	v.srtt = (v.srtt >> 3) / 1000;
	v.rttvar_us /= 1000;

	bpf_map_update_elem(&events, &index, &v, BPF_ANY);

	return 0;
}
