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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(UdpArgs));
	__uint(max_entries, 512);
} makeSkb SEC(".maps");



///

__attribute__((always_inline))
static int setFourTupleKey(FourTupleKey *key, struct sock *sk) {
	short unsigned int family = 0;
	int ret = 0;
	
	bpf_probe_read_kernel(&family, sizeof(family), &(sk->__sk_common.skc_family));
	if (family == AF_INET) {
		bpf_probe_read_kernel(&key->saddr, sizeof(key->saddr), &(sk->__sk_common.skc_rcv_saddr));
		bpf_probe_read_kernel(&key->daddr, sizeof(key->daddr), &(sk->__sk_common.skc_daddr));
		ret = ETH_P_IP;
		key->ipv = 4;
 
	} else if (family == AF_INET6){
		bpf_probe_read_kernel(&key->saddrv6, sizeof(key->saddrv6), &(sk->__sk_common.skc_v6_rcv_saddr));
		bpf_probe_read_kernel(&key->daddrv6, sizeof(key->daddrv6), &(sk->__sk_common.skc_v6_daddr));
		ret = ETH_P_IPV6;
		key->ipv = 6;
	} else {
		return BPF_RET_ERROR;
	}


	bpf_probe_read_kernel(&key->sport, sizeof(key->sport), &(sk->__sk_common.skc_num));
	bpf_probe_read_kernel(&key->dport, sizeof(key->dport), &(sk->__sk_common.skc_dport));
	key->dport = bpf_ntohs(key->dport);

	return ret;

}

__attribute__((always_inline))
static int setProcessSessionKey(ProcessSessionKey *key, struct sock *sk) {
	u64 pid = bpf_get_current_pid_tgid();
	key->pid = pid;

	int ret = setFourTupleKey(&key->fourTuple, sk);
	return ret;
}


__attribute__((always_inline))
static int closeSessionFunc(struct sock *sk) {
	ProcessSessionKey pKey = {0, };
	int ret = setFourTupleKey(&pKey.fourTuple, sk);
	if (ret != BPF_RET_OK) {
		return ret;
	}

	SessionInfo *sInfo = bpf_map_lookup_elem(&sessionInfoMap, &pKey.fourTuple);
	if (sInfo == NULL) {
		return BPF_RET_ERROR;
	}

	int i = 0;
	for (i = 0; i < MAX_PID_LIST; i++) {

		bpf_probe_read_kernel(&pKey.pid, sizeof(u32), &sInfo->pid[i]);
		if (pKey.pid == 0) break;

		CloseStateValue dummy;
		__builtin_memset(&dummy, 0, sizeof(CloseStateValue));
		bpf_map_update_elem(&closeStateMap, &pKey, &dummy, BPF_NOEXIST);

		CloseStateValue *closeState = bpf_map_lookup_elem(&closeStateMap, &pKey);
		if (closeState == NULL) {
			continue;
		}


		SessionStateValue *sValue = bpf_map_lookup_elem(&sessionStateMap, &pKey);
		if (sValue == NULL) {
			continue;
		}

		closeState->sessionState.ether = sValue->ether;
		closeState->sessionState.direction = sValue->direction;
		closeState->sessionState.protocol = sValue->protocol;
		closeState->sessionState.sendCount += sValue->sendCount;
		closeState->sessionState.recvCount += sValue->recvCount;
		closeState->sessionState.sendByte += sValue->sendByte;
		closeState->sessionState.recvByte += sValue->recvByte;

		bpf_map_delete_elem(&sessionStateMap, &pKey);

		TCPStateValue *tcpValue = bpf_map_lookup_elem(&tcpStateMap, &pKey);
		if (tcpValue == NULL) {
			continue;
		}

		closeState->tcpState.retransCount += tcpValue->retransCount;
		closeState->tcpState.lostCount += tcpValue->lostCount;
		if (closeState->tcpState.latency < tcpValue->latency) {
			closeState->tcpState.latency = tcpValue->latency;
		}
		if (closeState->tcpState.jitter < tcpValue->jitter) {
			closeState->tcpState.jitter = tcpValue->jitter;
		}

		bpf_map_delete_elem(&tcpStateMap, &pKey);
	}

	bpf_map_delete_elem(&sessionInfoMap, &pKey.fourTuple);
	return BPF_RET_OK;

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
			SessionInfo *sessionInfo = bpf_map_lookup_elem(&sessionInfoMap, &key->fourTuple);
			if (sessionInfo != NULL && sessionInfo->bindState == BIND) {
				sValue->direction = IN;
			} else {
				//TODO 변경 가능성 검토
				//agent에서 처리 가능하다면 return 하지말고 데이터 채워야됨
				if (protocol == IPPROTO_TCP) {
					return BPF_RET_UNKNOWN;
				} else if (protocol == IPPROTO_UDP) {
					return BPF_RET_UNKNOWN;
				}	
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
		if (sendCount > 0)
			__sync_fetch_and_add(&sValue->sendCount, sendCount);
		if (recvCount > 0)
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
static int setTCPState(ProcessSessionKey *key, struct tcp_sock *ts) {
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

	//tcpValue->state |= (1 << state);

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

__attribute__((always_inline))
static int setSessionInfo(FourTupleKey *key, u16 state, u32 pid, u8 bind) {

	SessionInfo dummy;
	__builtin_memset(&dummy, 0, sizeof(SessionInfo));
	bpf_map_update_elem(&sessionInfoMap, key, &dummy, BPF_NOEXIST);


	SessionInfo *sInfo = bpf_map_lookup_elem(&sessionInfoMap, key);
	if (sInfo == NULL) {
		return BPF_RET_ERROR;
	}

	if (sInfo->bindState != BIND) {
		if (bind != BIND) {
			return BPF_RET_ERROR;
		}
		sInfo->bindState = bind;
	}

	sInfo->state |= (1 << state);

	int i = 0;
	int check = 0;
	for (; i < MAX_PID_LIST; i++) {
		if (sInfo->pid[i] == pid) {
			check = 1;
			break;
		}
		if (sInfo->pid[i] == 0) {
			check = 1;
			sInfo->pid[i] = pid;
			break;
		}
	}

	if (check == 0) {
		return BPF_RET_ERROR;
	}

	return BPF_RET_OK;
}

///
// TCP

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
	//BindCheckValue bindValue;
	//bindValue.bindState = BIND;

	//bpf_map_update_elem(&bindCheckMap, &key.fourTuple, &bindValue, BPF_ANY);
	

	int ret = setSessionInfo(&key.fourTuple, TCP_ESTABLISHED, key.pid, BIND);
	if (ret != BPF_RET_OK) {
		return ret;
	}

	bpf_printk("inet_csk_accept(ret), %d ", key.fourTuple.sport);
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

	u8 state = TCP_SYN_SENT;
	ret = setSessionInfo(&key.fourTuple, state, key.pid, BIND);
	if (ret != BPF_RET_OK) {
		return ret;
	}

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	if (ts == NULL) {
		return BPF_RET_ERROR;
	}

	if ((ret = setSessionState(&key, ipv, IPPROTO_TCP, OUT, 0, 0, 0, 0)) != BPF_RET_OK) {
		return BPF_RET_ERROR;
	}


	if (setTCPState(&key, ts) == BPF_RET_ERROR) {
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
	int ret = setSessionInfo(&key.fourTuple, state, key.pid, NOT_BIND);
	if (ret != BPF_RET_OK) {
		return ret;
	}

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	if (setTCPState(&key, ts) == BPF_RET_ERROR) {
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

	int ret = setSessionInfo(&key.fourTuple, state, key.pid, NOT_BIND);
	if (ret != BPF_RET_OK) {
		return ret;
	}

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	if (setTCPState(&key, ts) == BPF_RET_ERROR) {
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
		bpf_printk("fail set pKey\n");
		return BPF_RET_ERROR;
	}

	u8 state = TCP_ESTABLISHED;
	int ret = setSessionInfo(&key.fourTuple, state, key.pid, NOT_BIND);
	if (ret != BPF_RET_OK) {
		//bpf_printk("fail set sInfo %d, \n", key.fourTuple.sport);
		return ret;
	}

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	if (ts == NULL) {
		bpf_printk("fail ts\n");
		return BPF_RET_ERROR;
	}
	u32 sendCount;
	u32 recvCount;

	getTCPPacketCount(ts, &sendCount, &recvCount);
	if (sendCount == (u32)-1 || recvCount == (u32)-1) {
		return BPF_RET_ERROR;
	}

	if ((ret = setSessionState(&key, ipv, IPPROTO_TCP, UNKNOWN, sendByte, sendCount, recvByte, recvCount)) != BPF_RET_OK) {
		//bpf_printk("fail set Session Sate\n");
		return BPF_RET_ERROR;
	}

	if (setTCPState(&key, ts) == BPF_RET_ERROR) {
		bpf_printk("fail set Tcp State\n");
		return BPF_RET_ERROR;
	}

	bpf_printk("tcp_sendmsg(ret) - %d\n");
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
	//bpf_printk("tcp_cleanup_rbuf(ret) start\n");
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

	u8 state = TCP_ESTABLISHED;
	int ret = setSessionInfo(&key.fourTuple, state, key.pid, NOT_BIND);
	if (ret != BPF_RET_OK) {
		return ret;
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

	if ((ret = setSessionState(&key, ipv, IPPROTO_TCP, UNKNOWN, sendByte, sendCount, recvByte, recvCount)) != BPF_RET_OK) {
		return BPF_RET_ERROR;
	}

	if (setTCPState(&key, ts) == BPF_RET_ERROR) {
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
	//bpf_map_delete_elem(&bindCheckMap, &key.fourTuple);
	
	closeSessionFunc(sk);
	bpf_printk("tcp_close\n");

	return BPF_RET_OK;
}

/*
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
*/

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




#if 0

///
// UDP
SEC("kprobe/inet_bind")
int kprobe__inet_bind(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid();
	bpf_printk("inet_bind - %d\n", pid);

	struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
	struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);

	if (sock == NULL || addr == NULL) return BPF_RET_ERROR;

	u16 type = 0;
	bpf_probe_read_kernel(&type, sizeof(type), &sock->type);
	if ((type & SOCK_DGRAM) == 0) {
		return BPF_RET_ERROR;
	}

	u16 sin_port = 0;
	bpf_probe_read_kernel(&sin_port, sizeof(u16), &(((struct sockaddr_in *)addr)->sin_port));


	sin_port = bpf_ntohs(sin_port);
	if (sin_port == 0) {
		return BPF_RET_ERROR;
	}
	bpf_printk("bind : %d\n", sin_port);


	BindCheckValue bindValue;
	bindValue.bindState = BIND;
	bpf_map_update_elem(&udpBindCheckMap, &sin_port, &bindValue, BPF_ANY);


	return 0;
}

/*
SEC("kretprobe/inet_bind")
int kretprobe__inet_bind(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid();
	bpf_printk("inet_bind(ret) - %d\n", pid);

	struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
	struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);

	if (sock == NULL || addr == NULL) return BPF_RET_ERROR;

	u16 type = 0;
	bpf_probe_read_kernel(&type, sizeof(type), &sock->type);
	if ((type & SOCK_DGRAM) == 0) {
		return BPF_RET_ERROR;
	}

	u16 sin_port = 0;
	bpf_probe_read_kernel(&sin_port, sizeof(u16), &(((struct sockaddr_in *)addr)->sin_port));


	sin_port = bpf_ntohs(sin_port);
	if (sin_port == 0) {
		return BPF_RET_ERROR;
	}
	bpf_printk("bind(ret) : %d\n", sin_port);


	BindCheckValue bindValue;
	bindValue.bindState = BIND;
	bpf_map_update_elem(&udpBindCheckMap, &sin_port, &bindValue, BPF_ANY);



	return BPF_RET_OK;
}
SEC("kprobe/__inet_bind")
int kprobe__inet_bind(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid();
	bpf_printk("__inet_bind - %d\n", pid);
	return 0;
}

SEC("kretprobe/__inet_bind")
int kretprobe__inet_bind(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid();
	bpf_printk("__inet_bind(ret) - %d\n", pid);

	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	
	ProcessSessionKey key;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if (setProcessSessionKey(&key, sk, AF_INET) == BPF_RET_ERROR) {
		return BPF_RET_ERROR;
	}

	bpf_printk("key - %d %d \n", key.fourTuple.sport, key.fourTuple.dport);

	return 0;
}
*/

SEC("kprobe/ip_make_skb")
int kprobe__ip_make_skb(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid();
	bpf_printk("ip_make_skb - %d\n", pid);

	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	int len = PT_REGS_PARM5(ctx);
	struct flowi4 *fl4 = (struct flowi4 *)PT_REGS_PARM2(ctx);

	UdpArgs udpArgs = {};

	bpf_printk("%p : %d : %p", sk, len, fl4);
	bpf_probe_read_kernel(&udpArgs.sk, sizeof(udpArgs.sk), &sk);
	bpf_probe_read_kernel(&udpArgs.len, sizeof(udpArgs.len), &len);
	bpf_probe_read_kernel(&udpArgs.fl4, sizeof(udpArgs.fl4), &fl4);

	bpf_map_update_elem(&makeSkb, &pid, &udpArgs, BPF_ANY);
	return 0;
}

SEC("kretprobe/ip_make_skb")
int kretprobe__ip_make_skb(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid();

	/*
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	int size = PT_REGS_PARM5(ctx);
	size -= sizeof(struct udphdr);
*/
	UdpArgs *udpArgs;
	udpArgs = bpf_map_lookup_elem(&makeSkb, &pid);
	if (udpArgs == NULL) {
		return BPF_RET_ERROR;
	}

	struct sock *sk = udpArgs->sk;
	if (sk == NULL) {
		return BPF_RET_ERROR;
	}
	struct flowi4 *fl4 = udpArgs->fl4;
	if (fl4 == NULL) {
		return BPF_RET_ERROR;
	}
	int len = udpArgs->len;
	len -= sizeof(struct udphdr);
	bpf_printk("%p : %d : %p", sk, len, fl4);
	ProcessSessionKey key;
	int ipv;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if ((ipv = setProcessSessionKey(&key, sk)) == BPF_RET_ERROR) {
		bpf_printk("SessionKey Error\n");
		bpf_probe_read_kernel(&key.fourTuple.saddr, sizeof(key.fourTuple.saddr), &fl4->saddr);
		bpf_probe_read_kernel(&key.fourTuple.daddr, sizeof(key.fourTuple.daddr), &fl4->daddr);

		bpf_probe_read_kernel(&key.fourTuple.sport, sizeof(key.fourTuple.sport), &fl4->uli.ports.sport);
		bpf_probe_read_kernel(&key.fourTuple.dport, sizeof(key.fourTuple.dport), &fl4->uli.ports.dport);
		key.pid = pid;

	}
	bpf_printk("key - %d %d \n", key.fourTuple.sport, key.fourTuple.dport);

	int ret;
	if ((ret = setSessionState(&key, ipv, IPPROTO_UDP, UNKNOWN, 1, 1, 0, 0)) != BPF_RET_OK) {
		bpf_printk("SessionState Error\n");
		return BPF_RET_ERROR;
	}

	bpf_printk("ip_make_skb(ret) - %d\n", pid);
	return 0;
}

SEC("kprobe/udp_recvmsg")
int kprobe__udp_recvmsg(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid();
	bpf_printk("udp_recvmsg - %d\n", pid);
	return 0;
}

SEC("kretprobe/udp_recvmsg")
int kretprobe_udp_recvmsg(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid();
	bpf_printk("udp_recvmsg(ret) - %d\n", pid);
	return 0;
}


SEC("kprobe/skb_consume_udp")
int kprobe__skb_consume_udp(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid();
	bpf_printk("skb_consume_udp - %d\n", pid);
	return 0;
}

SEC("kretprobe/skb_consume_udp")
int kretprobe__skb_consume_udp(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid();
	bpf_printk("skb_consume_udp(ret) - %d\n", pid);
	return 0;
}


#endif
