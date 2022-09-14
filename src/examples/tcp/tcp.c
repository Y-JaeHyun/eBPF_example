// +build ignore

#define __TARGET_ARCH_x86
//#include "common.h"

#define AF_INET 2
#define AF_INET6 10

#define INBOUND 1
#define OUTBOUND 2

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"

/////////////////////////////////////////////////////////
char __license[] SEC("license") = "GPL";

struct nKey {
	u16 sport;
	u16 dport;
	union {
		u32 saddr;
		u8 saddrv6[16];
	};
	union {
		u32 daddr;
		u8 daddrv6[16];
	};
	u32 pid;
};

struct statusValue{
	u32 totalCount;
	u32 connectCount;
	u32 estabilishCount;
	u32 sendCount;
	u32 recvCount;
	u32 closeCount;
	u32 retransmissionCount;
	u32 sendByte;
	u32 recvByte;
	u32 srtt;
	u32 mdev_us;
	u32 status;
	u8 bound;
};

struct nKey *unused_key_t  __attribute__((unused));
struct statusValue *unused_value_t  __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(void *));
	__uint(max_entries, 512);
} connectSock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(void *));
	__uint(max_entries, 512);
} acceptSock SEC(".maps");



struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(void *));
	__uint(max_entries, 512);
} sendSock SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct nKey));
	__uint(value_size, sizeof(struct statusValue));
	__uint(max_entries, 1024);
} statusMap SEC(".maps");


///
__attribute__((always_inline))
static int setNKey4Tuple(struct nKey *k, struct sock *sk) {
	short unsigned int family = 0;
	bpf_probe_read_kernel(&family, sizeof(family), &(sk->__sk_common.skc_family));


	if (family == AF_INET) {
		bpf_probe_read_kernel(&k->saddr, sizeof(k->saddr), &(sk->__sk_common.skc_rcv_saddr));
		bpf_probe_read_kernel(&k->daddr, sizeof(k->daddr), &(sk->__sk_common.skc_daddr));
 
	} else if (family == AF_INET6){
		bpf_probe_read_kernel(&k->saddrv6, sizeof(k->saddrv6), &(sk->__sk_common.skc_v6_rcv_saddr));
		bpf_probe_read_kernel(&k->daddrv6, sizeof(k->daddrv6), &(sk->__sk_common.skc_v6_daddr));
	} else {
		return -1;
	}

	bpf_probe_read_kernel(&k->sport, sizeof(k->sport), &(sk->__sk_common.skc_num));
	bpf_probe_read_kernel(&k->dport, sizeof(k->dport), &(sk->__sk_common.skc_dport));
	k->dport = bpf_ntohs(k->dport);
	return 0;
}

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

	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&sendSock, &pid, &sk, BPF_ANY);


	return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe__tcp_sendmsg(struct pt_regs*ctx) {
	const char fmt_str[] = "tcp_sendmsg(ret)\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));

	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&sendSock, &pid);
	if (skpp == 0) {

		return -1;	// missed entry
	}

	struct sock *sk = *skpp;
	bpf_map_delete_elem(&sendSock, &pid);

	struct nKey k;
	__builtin_memset(&k, 0, sizeof(struct nKey));

	if (setNKey4Tuple(&k, sk) == -1) {
		return -1;
	}
	k.pid = pid;

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	struct statusValue *v;
	v = bpf_map_lookup_elem(&statusMap, &k);

	if (v != NULL) {
		u32 tSrtt;
		u32 tMdev;
		u32 sByte;
		u32 rByte;

		bpf_probe_read_kernel(&tSrtt, sizeof(tSrtt), &ts->srtt_us);
		bpf_probe_read_kernel(&tMdev, sizeof(tMdev), &ts->mdev_us);

		v->srtt = (v->srtt * v->totalCount + tSrtt) / (v->totalCount + 1);
		v->mdev_us = (v->mdev_us * v->totalCount + tMdev) / (v->totalCount + 1);

		v->totalCount++;
		v->sendCount++;

		bpf_probe_read_kernel(&sByte, sizeof(sByte), &ts->segs_out);
		bpf_probe_read_kernel(&rByte, sizeof(rByte), &ts->segs_in);
		
		__sync_fetch_and_add(&v->sendByte, sByte);
		__sync_fetch_and_add(&v->recvByte, rByte);
		

		bpf_map_update_elem(&statusMap, &k, v, BPF_ANY);

	} else {
		return -1;
	}

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

	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&acceptSock, &pid, &sk, BPF_ANY);


	return 0;
}

SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs* ctx) {
	const char fmt_str[] = "inet_csk_accept(ret)\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));

	u64 pid = bpf_get_current_pid_tgid();
	struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
	struct nKey k;
	__builtin_memset(&k, 0, sizeof(struct nKey));

	if (setNKey4Tuple(&k, sk) == -1) {
		return -1;
	}
	k.pid = pid;

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	struct statusValue *v;
	v = bpf_map_lookup_elem(&statusMap, &k);

	if (v != NULL) {
		u32 tSrtt;
		u32 tMdev;

		bpf_probe_read_kernel(&tSrtt, sizeof(tSrtt), &ts->srtt_us);
		bpf_probe_read_kernel(&tMdev, sizeof(tMdev), &ts->mdev_us);

		v->srtt = (v->srtt * v->totalCount + tSrtt) / (v->totalCount + 1);
		v->mdev_us = (v->mdev_us * v->totalCount + tMdev) / (v->totalCount + 1);

		v->totalCount++;
		v->connectCount++;

		bpf_map_update_elem(&statusMap, &k, v, BPF_ANY);

	} else {
		struct statusValue v;
		// TODO : Check, memset 없는 경우permision denied
		// https://github.com/iovisor/bcc/issues/2623
		__builtin_memset(&v, 0, sizeof(struct statusValue));

		bpf_probe_read_kernel(&v.srtt, sizeof(v.srtt), &ts->srtt_us);
		bpf_probe_read_kernel(&v.mdev_us, sizeof(v.mdev_us), &ts->mdev_us);
		v.connectCount = 1;
		v.totalCount = 1;
		v.bound = INBOUND;
		bpf_map_update_elem(&statusMap, &k, &v, BPF_ANY);
	}


	return 0;
}

#if 1
SEC("kprobe/tcp_connect")
int kprobe__tcp_connect(struct pt_regs *ctx)
{
	const char fmt_str[] = "tcp_connect\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));

	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&connectSock, &pid, &sk, BPF_ANY);

	return 0;
}

SEC("kretprobe/tcp_connect")
int kretprobe__tcp_connect(struct pt_regs *ctx)
{
	const char fmt_str[] = "tcp_connect(ret)\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&connectSock, &pid);
	if (skpp == 0) {
		return -1;	// missed entry
	}

	struct sock *sk = *skpp;
	bpf_map_delete_elem(&connectSock, &pid);
	int ret = PT_REGS_RC(ctx);
	if (ret != 0) {

		// socket __sk_common.{skc_rcv_saddr, ...}
		return -1;
	}

	struct nKey k;
	__builtin_memset(&k, 0, sizeof(struct nKey));

	if (setNKey4Tuple(&k, sk) == -1) {
		return -1;
	}
	k.pid = pid;

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	struct statusValue *v;
	v = bpf_map_lookup_elem(&statusMap, &k);

	if (v != NULL) {
		u32 tSrtt;
		u32 tMdev;

		bpf_probe_read_kernel(&tSrtt, sizeof(tSrtt), &ts->srtt_us);
		bpf_probe_read_kernel(&tMdev, sizeof(tMdev), &ts->mdev_us);

		v->srtt = (v->srtt * v->totalCount + tSrtt) / (v->totalCount + 1);
		v->mdev_us = (v->mdev_us * v->totalCount + tMdev) / (v->totalCount + 1);

		v->totalCount++;
		v->connectCount++;
		bpf_map_update_elem(&statusMap, &k, v, BPF_ANY);

	} else {
		struct statusValue v;
		// TODO : Check, memset 없는 경우permision denied
		// https://github.com/iovisor/bcc/issues/2623
		__builtin_memset(&v, 0, sizeof(struct statusValue));

		bpf_probe_read_kernel(&v.srtt, sizeof(v.srtt), &ts->srtt_us);
		bpf_probe_read_kernel(&v.mdev_us, sizeof(v.mdev_us), &ts->mdev_us);
		v.connectCount = 1;
		v.totalCount = 1;
		v.bound = OUTBOUND;
		bpf_map_update_elem(&statusMap, &k, &v, BPF_ANY);
	}



	return 0;
}

#else

SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	const char fmt_str[] = "tcp_v4_connect\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));

	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&connectSock, &pid, &sk, BPF_ANY);

	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	const char fmt_str[] = "tcp_v4_connect(ret)\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&connectSock, &pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	struct sock *sk = *skpp;
	bpf_map_delete_elem(&connectSock, &pid);
	int ret = PT_REGS_RC(ctx);
	if (ret != 0) {

		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	short unsigned int family = 0;

	bpf_probe_read_kernel(&family, sizeof(family), &(sk->__sk_common.skc_family));

	struct nKey k;
	struct statusValue v;
	__builtin_memset(&v, 0, sizeof(struct statusValue));

	struct tcp_sock *ts = (struct tcp_sock*)sk;

	bpf_probe_read_kernel(&k.saddr, sizeof(k.saddr), &(sk->__sk_common.skc_rcv_saddr));
	bpf_probe_read_kernel(&k.daddr, sizeof(k.daddr), &(sk->__sk_common.skc_daddr));
	bpf_probe_read_kernel(&k.sport, sizeof(k.sport), &(sk->__sk_common.skc_num));
	bpf_probe_read_kernel(&k.dport, sizeof(k.dport), &(sk->__sk_common.skc_dport));
	k.dport = bpf_ntohs(k.dport);
	k.pid = pid;

	bpf_probe_read_kernel(&v.srtt, sizeof(v.srtt), &ts->srtt_us);
	v.srtt = 0;
	//v.rttvar = 0;
	v.status = 2;

	bpf_map_update_elem(&statusMap, &k, &v, BPF_ANY);
	return 0;
}
#endif
SEC("kprobe/tcp_cleanup_rbuf")
int kprobe__tcp__cleanup_rbpf(struct pt_regs *ctx) {
	const char fmt_str[] = "tcp_cleanup_rbuf\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));

	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&sendSock, &pid, &sk, BPF_ANY);

	return 0;
}

SEC("kretprobe/tcp_cleanup_rbuf")
int kretprobe__tcp__cleanup_rbpf(struct pt_regs *ctx) {
	const char fmt_str[] = "tcp_cleanup_rbuf(ret)\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));

	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&sendSock, &pid);
	if (skpp == 0) {

		return -1;	// missed entry
	}

	struct sock *sk = *skpp;
	bpf_map_delete_elem(&sendSock, &pid);

	struct nKey k;
	__builtin_memset(&k, 0, sizeof(struct nKey));

	if (setNKey4Tuple(&k, sk) == -1) {
		return -1;
	}
	k.pid = pid;

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	struct statusValue *v;
	v = bpf_map_lookup_elem(&statusMap, &k);

	if (v != NULL) {
		u32 tSrtt;
		u32 tMdev;
		u32 sByte;
		u32 rByte;

		bpf_probe_read_kernel(&tSrtt, sizeof(tSrtt), &ts->srtt_us);
		bpf_probe_read_kernel(&tMdev, sizeof(tMdev), &ts->mdev_us);

		v->srtt = (v->srtt * v->totalCount + tSrtt) / (v->totalCount + 1);
		v->mdev_us = (v->mdev_us * v->totalCount + tMdev) / (v->totalCount + 1);

		v->totalCount++;
		v->recvCount++;

		bpf_probe_read_kernel(&sByte, sizeof(sByte), &ts->segs_out);
		bpf_probe_read_kernel(&rByte, sizeof(rByte), &ts->segs_in);
		
		__sync_fetch_and_add(&v->sendByte, sByte);
		__sync_fetch_and_add(&v->recvByte, rByte);
		

		bpf_map_update_elem(&statusMap, &k, v, BPF_ANY);

	} else {
		return -1;
	}





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

