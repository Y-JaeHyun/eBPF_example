// +build ignore

#define __TARGET_ARCH_x86
//#include "common.h"

#define AF_INET 2
#define AF_INET6 10

#include "tcp.h"


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
} sendSock SEC(".maps");


///
__attribute__((always_inline))
static int setProcessSessionKey(ProcessSessionKey *key, struct sock *sk) {
	short unsigned int family = 0;
	int ret = 0;
	bpf_probe_read_kernel(&family, sizeof(family), &(sk->__sk_common.skc_family));

	if (family == AF_INET) {
		bpf_probe_read_kernel(&key->fourTuple.sip.saddr, sizeof(key->fourTuple.sip.saddr), &(sk->__sk_common.skc_rcv_saddr));
		bpf_probe_read_kernel(&key->fourTuple.dip.daddr, sizeof(key->fourTuple.dip.daddr), &(sk->__sk_common.skc_daddr));
		ret = ETH_P_IP;
		key->fourTuple.ipv = 4;
 
	} else if (family == AF_INET6){
		bpf_probe_read_kernel(&key->fourTuple.sip.saddrv6, sizeof(key->fourTuple.sip.saddrv6), &(sk->__sk_common.skc_v6_rcv_saddr));
		bpf_probe_read_kernel(&key->fourTuple.dip.daddrv6, sizeof(key->fourTuple.dip.daddrv6), &(sk->__sk_common.skc_v6_daddr));
		ret = ETH_P_IPV6;
		key->fourTuple.ipv = 6;
	} else {
		return BPF_RET_ERROR;
	}

	bpf_probe_read_kernel(&key->fourTuple.sport, sizeof(key->fourTuple.sport), &(sk->__sk_common.skc_num));
	bpf_probe_read_kernel(&key->fourTuple.dport, sizeof(key->fourTuple.dport), &(sk->__sk_common.skc_dport));
	key->fourTuple.dport = bpf_ntohs(key->fourTuple.dport);

	u64 pid = bpf_get_current_pid_tgid();
	key->pid = pid;
	return ret;
}

__attribute__((always_inline))
static void getTCPPacketCount(struct tcp_sock *ts, u32 *sendCount, u32 *recvCount) {
	bpf_probe_read_kernel(sendCount, sizeof(*sendCount), &ts->segs_out);
	bpf_probe_read_kernel(recvCount, sizeof(*recvCount), &ts->segs_in);
}

__attribute__((always_inline))
static int setSessionState(ProcessSessionKey *key,u16 ether, u8 protocol, u8 direction, u32 sendByte, u32 sendCount, u32 recvByte, u32 recvCount) {
	SessionStateValue *sValue = bpf_map_lookup_elem(&sessionStateMap, key);
	SessionStateValue dummy;
	__builtin_memset(&dummy, 0, sizeof(SessionStateValue));
	if (sValue == NULL) { 
		sValue = &dummy;
	}

	if (sValue->direction == UNKNOWN) {
		if (direction == UNKNOWN) {
			BindCheckValue *bindCheckValue = bpf_map_lookup_elem(&bindCheckMap, &key->fourTuple);
			if (bindCheckValue != NULL && bindCheckValue->bindState == BIND) {
				sValue->direction = IN;
			} else {
				return BPF_RET_UNKNOWN;
			}	
		} else {
			sValue->direction = direction;
		}
	}

	sValue->ether = ether;
	sValue->protocol = protocol;
	if (protocol == IPPROTO_TCP) {
		sValue->sendCount = sendCount;
		sValue->recvCount = recvCount;
	} else {
		__sync_fetch_and_add(&sValue->sendCount, sendCount);
		__sync_fetch_and_add(&sValue->recvCount, recvCount);
	}

	if (sendByte > 0)
		__sync_fetch_and_add(&sValue->sendByte, sendByte);
	if (recvByte > 0)
		__sync_fetch_and_add(&sValue->recvByte, recvByte);

	bpf_map_update_elem(&sessionStateMap, key, sValue, BPF_ANY);

	return BPF_RET_OK;
}

__attribute__((always_inline))
static int setTCPState(ProcessSessionKey *key, struct tcp_sock *ts, u16 state) {
	TCPStateValue dummy;
	__builtin_memset(&dummy, 0, sizeof(TCPStateValue));
	bpf_map_update_elem(&tcpStateMap, key, &dummy, BPF_NOEXIST);

	TCPStateValue *tcpValue = bpf_map_lookup_elem(&tcpStateMap, key);
	if (tcpValue == NULL) {
		return BPF_RET_ERROR;
	}

	u32 tSrtt;
	u32 tMdev;

	bpf_probe_read_kernel(&tSrtt, sizeof(tSrtt), &ts->srtt_us);
	bpf_probe_read_kernel(&tMdev, sizeof(tMdev), &ts->mdev_us);

	//https://elixir.bootlin.com/linux/v4.6/source/net/ipv4/tcp.c#L2686
	tcpValue->latency = tSrtt >> 3;
	tcpValue->jitter = tMdev >> 2;

	tcpValue->state |= (1 << state);

	u32 lostCount;
	u32 retransCount;

	bpf_probe_read_kernel(&lostCount, sizeof(lostCount), &ts->lost_out);
	bpf_probe_read_kernel(&retransCount, sizeof(retransCount), &ts->retrans_out);

	if (lostCount > 0)
		__sync_fetch_and_add(&tcpValue->lostCount, lostCount);
	if (retransCount > 0)
		__sync_fetch_and_add(&tcpValue->retransCount, retransCount);

	return BPF_RET_OK;
}

///

SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs* ctx) {
	struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
	if (sk == NULL) {
		return BPF_RET_ERROR;
	}

	ProcessSessionKey key;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if (setProcessSessionKey(&key, sk) == BPF_RET_ERROR) {
		return BPF_RET_ERROR;
	}

	// TODO : CHECK
	BindCheckValue bindValue;
	bindValue.bindState = BIND;

	bpf_map_update_elem(&bindCheckMap, &key.fourTuple, &bindValue, BPF_ANY);

	bpf_printk("inet_csk_accept(ret) - %d\n", key.pid);
	return BPF_RET_OK;
}

SEC("kprobe/tcp_connect")
int kprobe__tcp_connect(struct pt_regs *ctx) {
	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&connectSock, &pid, &sk, BPF_ANY);
	return BPF_RET_OK;
}

SEC("kretprobe/tcp_connect")
int kretprobe__tcp_connect(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&connectSock, &pid);
	if (skpp == NULL) {
		return BPF_RET_ERROR;
	}

	struct sock *sk = *skpp;
	bpf_map_delete_elem(&connectSock, &pid);
	int ret = PT_REGS_RC(ctx);
	if (ret != 0) {
		return BPF_RET_ERROR;
	}

	ProcessSessionKey key;
	int ipv;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if ((ipv = setProcessSessionKey(&key, sk)) == BPF_RET_ERROR) {
		return BPF_RET_ERROR;
	}

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	if (ts == NULL) {
		return BPF_RET_ERROR;
	}

	if ((ret = setSessionState(&key, ipv, IPPROTO_TCP, OUT, 0, 0, 0, 0)) != BPF_RET_OK) {
		return BPF_RET_ERROR;
	}

	u8 state = TCP_SYN_SENT;

	if (setTCPState(&key, ts, state) == BPF_RET_ERROR) {
		return BPF_RET_ERROR;
	}

	bpf_printk("tcp_connect(ret) - %d\n", key.pid);
	return BPF_RET_OK;
}


SEC("kprobe/tcp_finish_connect")
int kprobe__tcp_finish_connect(struct pt_regs* ctx) {
	struct sock *sk;
	sk = (struct sock *) PT_REGS_PARM1(ctx);
	if (sk == NULL) {
		return BPF_RET_ERROR;
	}

	ProcessSessionKey key;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if (setProcessSessionKey(&key, sk) == BPF_RET_ERROR) {
		return BPF_RET_ERROR;
	}

	u8 state = TCP_ESTABLISHED;
	struct tcp_sock *ts = (struct tcp_sock*)sk;
	if (setTCPState(&key, ts, state) == BPF_RET_ERROR) {
		return BPF_RET_ERROR;
	}

	bpf_printk("tcp_finish_connect - %d\n", key.pid);
	return BPF_RET_OK;
}

SEC("kprobe/tcp_set_state")
int kprobe__tcp_set_state(struct pt_regs* ctx) {
	u64 pid = bpf_get_current_pid_tgid();

	struct sock *sk;
	sk = (struct sock *) PT_REGS_PARM1(ctx);
	if (sk == NULL) {
		return BPF_RET_ERROR;
	}

	u32 state;
	state = PT_REGS_PARM2(ctx);

	if (state != TCP_ESTABLISHED || state != TCP_CLOSE) {
		return BPF_RET_ERROR;
	}

	ProcessSessionKey key;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if (setProcessSessionKey(&key, sk) == BPF_RET_ERROR) {
		return BPF_RET_ERROR;
	}

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	if (setTCPState(&key, ts, state) == BPF_RET_ERROR) {
		return BPF_RET_ERROR;
	}

	bpf_printk("tcp_set_state - %d\n", key.pid);
	return BPF_RET_OK;
}


SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs*ctx) {
	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&sendSock, &pid, &sk, BPF_ANY);

	return BPF_RET_OK;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe__tcp_sendmsg(struct pt_regs*ctx) {
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&sendSock, &pid);
	if (skpp == NULL) {
		return BPF_RET_ERROR;
	}
	bpf_map_delete_elem(&sendSock, &pid);

	struct sock *sk = *skpp;
	if (sk == NULL) {
		return BPF_RET_ERROR;
	}

	int sendByte = PT_REGS_RC(ctx);
	if (sendByte < 0) {
		return BPF_RET_ERROR;
	}
	int recvByte = 0;

	ProcessSessionKey key;
	int ipv;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if ((ipv = setProcessSessionKey(&key, sk)) == BPF_RET_ERROR) {
		return BPF_RET_ERROR;
	}

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	if (ts == NULL) {
		return BPF_RET_ERROR;
	}
	u32 sendCount;
	u32 recvCount;

	getTCPPacketCount(ts, &sendCount, &recvCount);
	if (sendCount == (u32)-1 || recvCount == (u32)-1) {
		return BPF_RET_ERROR;
	}

	int ret;
	if ((ret = setSessionState(&key, ipv, IPPROTO_TCP, UNKNOWN, sendByte, sendCount, recvByte, recvCount)) != BPF_RET_OK) {
		return BPF_RET_ERROR;
	}

	u8 state = 0;
	if (ret == BPF_RET_OK) {
		state = TCP_ESTABLISHED;
	}	

	if (setTCPState(&key, ts, state) == BPF_RET_ERROR) {
		return BPF_RET_ERROR;
	}
	bpf_printk("tcp_sendmsg(ret) - %d\n", key.pid);
	return BPF_RET_OK;
}

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe__tcp__cleanup_rbpf(struct pt_regs *ctx) {
	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&sendSock, &pid, &sk, BPF_ANY);

	return BPF_RET_OK;
}

SEC("kretprobe/tcp_cleanup_rbuf")
int kretprobe__tcp__cleanup_rbpf(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&sendSock, &pid);
	if (skpp == NULL) {
		return BPF_RET_ERROR;
	}
	bpf_map_delete_elem(&sendSock, &pid);

	struct sock *sk = *skpp;
	if (sk == NULL) {
		return BPF_RET_ERROR;
	}
	
	int recvByte = PT_REGS_PARM2(ctx);
	if (recvByte < 0) {
		return BPF_RET_ERROR;
	}
	int sendByte = 0;

	ProcessSessionKey key;
	int ipv;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if ((ipv = setProcessSessionKey(&key, sk)) == BPF_RET_ERROR) {
		return BPF_RET_ERROR;
	}

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	if (ts == NULL) {
		return BPF_RET_ERROR;
	}

	u32 sendCount;
	u32 recvCount;

	getTCPPacketCount(ts, &sendCount, &recvCount);
	if (sendCount == (u32)-1 || recvCount == (u32)-1) {
		return BPF_RET_ERROR;
	}

	int ret;
	if ((ret = setSessionState(&key, ipv, IPPROTO_TCP, UNKNOWN, sendByte, sendCount, recvByte, recvCount)) != BPF_RET_OK) {
		return BPF_RET_ERROR;
	}

	u8 state = 0;
	if (ret == BPF_RET_OK) {
		state = TCP_ESTABLISHED;
	}

	if (setTCPState(&key, ts, state) == BPF_RET_ERROR) {
		return BPF_RET_ERROR;
	}
	bpf_printk("tcp_cleanup_rbuf(ret) - %d\n", key.pid);
	return BPF_RET_OK;
}

SEC("kprobe/tcp_close")
int kprobe__tcp_close(struct pt_regs *ctx) {
	const char fmt_str[] = "tcp_close\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));

	u64 pid = bpf_get_current_pid_tgid();

	struct sock *sk;
	sk = (struct sock *) PT_REGS_PARM1(ctx);
	if (sk == NULL) {
		return BPF_RET_ERROR;
	}

	ProcessSessionKey key;
	int ipv;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if ((ipv = setProcessSessionKey(&key, sk)) == BPF_RET_ERROR) {
		return BPF_RET_ERROR;
	}

	CloseStateValue closeValue;
	__builtin_memset(&closeValue, 0, sizeof(CloseStateValue));

	SessionStateValue *sValue = bpf_map_lookup_elem(&sessionStateMap, &key);
	if (sValue == NULL) {
		return BPF_RET_ERROR;
	}
	//__builtin_memcpy(&closeValue.sessionState, sValue, sizeof(closeValue.sessionState));
	//bpf_map_delete_elem(&sessionStateMap, &key);

	TCPStateValue *tcpValue = bpf_map_lookup_elem(&tcpStateMap, &key);
	if (tcpValue == NULL) {
		return BPF_RET_ERROR;
	}
	tcpValue->state |= (1 << TCP_CLOSE);
	//__builtin_memcpy(&closeValue.tcpState, tcpValue, sizeof(closeValue.tcpState));
	//bpf_map_delete_elem(&tcpStateMap, &key);

	//bpf_map_update_elem(&closeStateMap, &key, &closeValue, BPF_ANY);

	return BPF_RET_OK;
}

SEC("kprobe/inet_csk_listen_stop")
int kprobe__inet_csk_listen_stop(struct pt_regs *ctx) {
	const char fmt_str[] = "inet_csk_listen_stop\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));

	u64 pid = bpf_get_current_pid_tgid();

	struct sock *sk;
	sk = (struct sock *) PT_REGS_PARM1(ctx);
	if (sk == NULL) {
		return BPF_RET_ERROR;
	}

	ProcessSessionKey key;
	int ipv;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if ((ipv = setProcessSessionKey(&key, sk)) == BPF_RET_ERROR) {
		return BPF_RET_ERROR;
	}

	CloseStateValue closeValue;
	__builtin_memset(&closeValue, 0, sizeof(CloseStateValue));

	SessionStateValue *sValue = bpf_map_lookup_elem(&sessionStateMap, &key);
	if (sValue == NULL) {
		return BPF_RET_ERROR;
	}
	//__builtin_memcpy(&closeValue.sessionState, sValue, sizeof(closeValue.sessionState));
	//bpf_map_delete_elem(&sessionStateMap, &key);

	TCPStateValue *tcpValue = bpf_map_lookup_elem(&tcpStateMap, &key);
	if (tcpValue == NULL) {
		return BPF_RET_ERROR;
	}
	tcpValue->state |= (1 << TCP_CLOSE);
	//__builtin_memcpy(&closeValue.tcpState, tcpValue, sizeof(closeValue.tcpState));
	//bpf_map_delete_elem(&tcpStateMap, &key);

	//bpf_map_update_elem(&closeStateMap, &key, &closeValue, BPF_ANY);

	return 0;

}


#if 0
SEC("kprobe/tcp_sendpage")
int kprobe__tcp_sendpage(struct pt_regs *ctx) {
	const char fmt_str[] = "tcp_sendpage\n";
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

#endif
