// +build ignore

#define __TARGET_ARCH_x86
#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "tcp_action.h"

#define AF_INET 2

char __license[] SEC("license") = "Dual MIT/GPL";

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
	u32 srtt_us;
	u32 mdev_us;     /* medium deviation			*/
	u32 mdev_max_us; /* maximal mdev for the last rtt period	*/
	u32 rttvar_us;   /* smoothed mdev_max			*/
	u32 rtt_seq;     /* sequence number to update rttvar	*/
} __attribute__((preserve_access_index));

/////////////////////////////////////////////////////////

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
struct event *unused_event __attribute__((unused));


/*
struct bpf_map_def SEC("maps/connectsock_ipv4") connectsock_ipv4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(void *),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};
*/

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(void *));
	__uint(max_entries, 1024);
	__uint(pinning, 0);
} connectsock_ipv4 SEC(".maps");

/*

struct bpf_map_def SEC("maps/tcptracer_status") tcptracer_status = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct tcptracer_status_t),
	.max_entries = 1,
	.pinning = 0,
	.namespace = "",
};
*/

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(struct tcptracer_status_t));
	__uint(max_entries, 1);
	__uint(pinning, 0);
} tcptracer_status SEC(".maps");


struct {
//	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, 0);
	__uint(value_size, sizeof(struct event));
	__uint(max_entries, 1024);
} events SEC(".maps");

SEC("kprobe/tcp_close")
int BPF_KPROBE(tcp_close, struct sock *sk) {
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


SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&connectsock_ipv4, &pid, &sk, BPF_ANY);

	return 0;
}

__attribute__((always_inline))
static int are_offsets_ready_v4(struct tcptracer_status_t *status, struct sock *skp, u64 pid) {
	u64 zero = 0;

	switch (status->state) {
		case TCPTRACER_STATE_UNINITIALIZED:
			return 0;
		case TCPTRACER_STATE_CHECKING:
			break;
		case TCPTRACER_STATE_CHECKED:
			return 0;
		case TCPTRACER_STATE_READY:
			return 1;
		default:
			return 0;
	}

	// Only accept the exact pid & tid. Extraneous connections from other
	// threads must be ignored here. Userland must take care to generate
	// connections from the correct thread. In Golang, this can be achieved
	// with runtime.LockOSThread.
	if (status->pid_tgid != pid)
		return 0;

	struct tcptracer_status_t new_status = { };
	new_status.state = TCPTRACER_STATE_CHECKED;
	new_status.pid_tgid = status->pid_tgid;
	new_status.what = status->what;
	new_status.offset_saddr = status->offset_saddr;
	new_status.offset_daddr = status->offset_daddr;
	new_status.offset_sport = status->offset_sport;
	new_status.offset_dport = status->offset_dport;
	new_status.offset_netns = status->offset_netns;
	new_status.offset_ino = status->offset_ino;
	new_status.offset_family = status->offset_family;
	new_status.offset_daddr_ipv6 = status->offset_daddr_ipv6;
	new_status.err = 0;
	new_status.saddr = status->saddr;
	new_status.daddr = status->daddr;
	new_status.sport = status->sport;
	new_status.dport = status->dport;
	new_status.netns = status->netns;
	new_status.family = status->family;

	int i;
	for (i = 0; i < 4; i++) {
		new_status.daddr_ipv6[i] = status->daddr_ipv6[i];
	}

	u32 possible_saddr;
	u32 possible_daddr;
	u16 possible_sport;
	u16 possible_dport;
	void *possible_skc_net;
	u32 possible_netns;
	u16 possible_family;
	long ret = 0;

	switch (status->what) {
		case GUESS_SADDR:
			possible_saddr = 0;
			bpf_probe_read(&possible_saddr, sizeof(possible_saddr), ((char *)skp) + status->offset_saddr);
			new_status.saddr = possible_saddr;
			break;
		case GUESS_DADDR:
			possible_daddr = 0;
			bpf_probe_read(&possible_daddr, sizeof(possible_daddr), ((char *)skp) + status->offset_daddr);
			new_status.daddr = possible_daddr;
			break;
		case GUESS_FAMILY:
			possible_family = 0;
			bpf_probe_read(&possible_family, sizeof(possible_family), ((char *)skp) + status->offset_family);
			new_status.family = possible_family;
			break;
		case GUESS_SPORT:
			possible_sport = 0;
			bpf_probe_read(&possible_sport, sizeof(possible_sport), ((char *)skp) + status->offset_sport);
			new_status.sport = possible_sport;
			break;
		case GUESS_DPORT:
			possible_dport = 0;
			bpf_probe_read(&possible_dport, sizeof(possible_dport), ((char *)skp) + status->offset_dport);
			new_status.dport = possible_dport;
			break;
		case GUESS_NETNS:
			possible_netns = 0;
			possible_skc_net = NULL;
			bpf_probe_read(&possible_skc_net, sizeof(void *), ((char *)skp) + status->offset_netns);
			// if we get a kernel fault, it means possible_skc_net
			// is an invalid pointer, signal an error so we can go
			// to the next offset_netns
			ret = bpf_probe_read(&possible_netns, sizeof(possible_netns), ((char *)possible_skc_net) + status->offset_ino);
			if (ret == -2) {
				new_status.err = 1;
				break;
			}
			new_status.netns = possible_netns;
			break;
		default:
			// not for us
			return 0;
	}

	bpf_map_update_elem(&tcptracer_status, &zero, &new_status, BPF_ANY);

	return 0;
}

__attribute__((always_inline))
static int are_offsets_ready_v6(struct tcptracer_status_t *status, struct sock *skp, u64 pid) {
	u64 zero = 0;

	switch (status->state) {
		case TCPTRACER_STATE_UNINITIALIZED:
			return 0;
		case TCPTRACER_STATE_CHECKING:
			break;
		case TCPTRACER_STATE_CHECKED:
			return 0;
		case TCPTRACER_STATE_READY:
			return 1;
		default:
			return 0;
	}

	// Only accept the exact pid & tid. Extraneous connections from other
	// threads must be ignored here. Userland must take care to generate
	// connections from the correct thread. In Golang, this can be achieved
	// with runtime.LockOSThread.
	if (status->pid_tgid != pid)
		return 0;

	struct tcptracer_status_t new_status = { };
	new_status.state = TCPTRACER_STATE_CHECKED;
	new_status.pid_tgid = status->pid_tgid;
	new_status.what = status->what;
	new_status.offset_saddr = status->offset_saddr;
	new_status.offset_daddr = status->offset_daddr;
	new_status.offset_sport = status->offset_sport;
	new_status.offset_dport = status->offset_dport;
	new_status.offset_netns = status->offset_netns;
	new_status.offset_ino = status->offset_ino;
	new_status.offset_family = status->offset_family;
	new_status.offset_daddr_ipv6 = status->offset_daddr_ipv6;
	new_status.err = 0;
	new_status.saddr = status->saddr;
	new_status.daddr = status->daddr;
	new_status.sport = status->sport;
	new_status.dport = status->dport;
	new_status.netns = status->netns;
	new_status.family = status->family;

	int i;
	for (i = 0; i < 4; i++) {
		new_status.daddr_ipv6[i] = status->daddr_ipv6[i];
	}

	u32 possible_daddr_ipv6[4] = { };
	switch (status->what) {
		case GUESS_DADDR_IPV6:
			bpf_probe_read(&possible_daddr_ipv6, sizeof(possible_daddr_ipv6), ((char *)skp) + status->offset_daddr_ipv6);

			int i;
			for (i = 0; i < 4; i++) {
				new_status.daddr_ipv6[i] = possible_daddr_ipv6[i];
			}
			break;
		default:
			// not for us
			return 0;
	}

	bpf_map_update_elem(&tcptracer_status, &zero, &new_status, BPF_ANY);

	return 0;
}

__attribute__((always_inline))
static int check_family(struct sock *sk, u16 expected_family) {
	struct tcptracer_status_t *status;
	u64 zero = 0;
	u16 family;
	family = 0;

	status = bpf_map_lookup_elem(&tcptracer_status, &zero);
	if (status == NULL || status->state != TCPTRACER_STATE_READY) {
		return 0;
	}

	bpf_probe_read(&family, sizeof(u16), ((char *)sk) + status->offset_family);

	return family == expected_family;
}

__attribute__((always_inline))
static int read_ipv4_tuple(struct ipv4_tuple_t *tuple, struct tcptracer_status_t *status, struct sock *skp)
{
	u32 saddr, daddr, net_ns_inum;
	u16 sport, dport;
	void *skc_net;

	saddr = 0;
	daddr = 0;
	sport = 0;
	dport = 0;
	skc_net = NULL;
	net_ns_inum = 0;

	bpf_probe_read(&saddr, sizeof(saddr), ((char *)skp) + status->offset_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), ((char *)skp) + status->offset_daddr);
	bpf_probe_read(&sport, sizeof(sport), ((char *)skp) + status->offset_sport);
	bpf_probe_read(&dport, sizeof(dport), ((char *)skp) + status->offset_dport);
	// Get network namespace id
	bpf_probe_read(&skc_net, sizeof(void *), ((char *)skp) + status->offset_netns);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), ((char *)skc_net) + status->offset_ino);

	tuple->saddr = saddr;
	tuple->daddr = daddr;
	tuple->sport = sport;
	tuple->dport = dport;
	tuple->netns = net_ns_inum;

	// if addresses or ports are 0, ignore
	if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
		return 0;
	}

	return 1;
}




SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	u64 zero = 0;
	struct tcptracer_status_t *status;

	skpp = bpf_map_lookup_elem(&connectsock_ipv4, &pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	struct sock *skp = *skpp;

	bpf_map_delete_elem(&connectsock_ipv4, &pid);

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	status = bpf_map_lookup_elem(&tcptracer_status, &zero);
	if (status == NULL || status->state == TCPTRACER_STATE_UNINITIALIZED) {
		return 0;
	}

	bpf_printk("aaa");

	/*
	if (!are_offsets_ready_v4(status, skp, pid)) {
		return 0;
	}

	// output
	struct ipv4_tuple_t t = { };
	if (!read_ipv4_tuple(&t, status, skp)) {
		return 0;
	}
	struct pid_comm_t p = { .pid = pid };
	bpf_get_current_comm(p.comm, sizeof(p.comm));
	bpf_map_update_elem(&tuplepid_ipv4, &t, &p, BPF_ANY);
*/

	return 0;
}

