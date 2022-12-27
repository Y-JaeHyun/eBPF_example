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
	__uint(value_size, sizeof(void *));
	__uint(max_entries, 512);
} recvSock SEC(".maps");



struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(ProcessSessionKey));
	__uint(max_entries, 512);
} udpSendSock SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(ProcessSessionKey));
	__uint(max_entries, 512);
} udpRecvSock SEC(".maps");


#define NONTYPE 0
#define UNSIGN 0x01
#define SIGN 0x02
#define STRING 0x03

#define U64 0x81
#define U32 0x41
#define U16 0x21
#define U8  0x11

#define S64 0x82
#define S32 0x42
#define S16 0x22
#define S8  0x12

#define ERROR 0
#define WARN 1
#define INFO 2
#define DEBUG 3

#define NONTYPOE 0
#define LOGMAP 1
#define LOGPIPE 2

#define GET_PID bpf_get_current_pid_tgid() & 0xFFFFFFFF;

// String, std library 사용 제약이 있어 별도 구현, 성능 보장안되기 떄문에 Release Mode에서 사용 어려움
#define LOG_PRINTK(logMessage, logLevel) \
	if (checkLogType != NONTYPE && checkLogLevel >= logLevel){ \
	LogMessage log = {0, }; \
	__builtin_memcpy(log.func, &__func__, sizeof(log.func)); \
	log.line = __LINE__; \
	__builtin_memcpy(log.message, logMessage, sizeof(log.message)); \
	log.level = logLevel; \
	log_printk(&log, checkLogType);}\
	
#define LOG_PRINTK_ARGS(logMessage, arg, type, logLevel) \
	if (checkLogType != NONTYPE && checkLogLevel >= logLevel){ \
	LogMessage log = {0, }; \
	__builtin_memcpy(log.func, &__func__, sizeof(log.func)); \
	log.line = __LINE__; \
	__builtin_memcpy(log.message, logMessage, sizeof(log.message)); \
	log.level = logLevel; \
	log_printk_arg(&log, arg, type, checkLogType); } \

__attribute__((always_inline))
static void log_printk(LogMessage *log, int logtype) {
	u64 pid = GET_PID;
	log->pid = pid;


	if (logtype == LOGMAP) {
		u32 idx = 0;
		u32 logMapIdx = 0;
		u32 *pIdx  = bpf_map_lookup_elem(&logMapIndex, &idx);
		int ret;

		if (pIdx != NULL) {
			logMapIdx = *pIdx;
		}

		//bpf_map_push_elem(&logMap, log, 0);
		ret = bpf_map_update_elem(&logMap, &logMapIdx, log, BPF_NOEXIST);
		bpf_printk("%d %u\n", ret, logMapIdx);

		if (ret == 0) {
			logMapIdx++;
			logMapIdx %= LOG_MAX_IDX;
			bpf_map_update_elem(&logMapIndex, &idx, &logMapIdx, BPF_ANY);
		}
	} else if (logtype == LOGPIPE) {
		bpf_printk("[%s][%d]\n", log->func, log->line);
		bpf_printk("\tMessage - %s\n", log->message);
		bpf_printk("\tPID - %llu\n", pid);
	}
}


//ASCII CODE BASE
//SIZE 16 고정, 추후 개선 필요
#if 1
#define ITOA16(value, result) \
	int i = 0; \
	for (; value && i < ARGS_LEN - 1; i++, value /= 10) {\
		result[i] = (value % 10) + 48;\
	}\
	result[i] = '\0';\
	int len = i;\
	int pivot = i / 2;\
	char temp;\
	for (i = 0; i < pivot; i++) {\
		temp = result[i];\
		result[i] = result[len -i -1];\
		result[len-i-1] = temp;\
	}\

#else

__attribute__((always_inline))
static void ITOA16(u64 value, char *str) {
	int i = 0;
	for (; value && i < ARGS_LEN - 1; i++, value /= 10) {
		str[i] = (value % 10) + 48;	
	}
	str[i] = '\0';
	int len = i;
	int pivot = i / 2;
	char temp;
	for (i = 0; i < pivot; i++) {
		temp = str[i];
		str[i] = str[len - i - 1];
		str[len-i-1] = temp;

	}
}

#endif

#define ATOI1(value, result) \
	result = value[0]; \
	result -= 48;\
	

__attribute__((always_inline))
static void log_printk_arg(LogMessage *log,  void *arg, int type, int logtype) {
	if (type == NONTYPE || arg == NULL) return;
	u64 pid = GET_PID;

	if (type & UNSIGN) {
		char numArg[ARGS_LEN] = {0, };
		type ^= UNSIGN;
		if (type & U64) {
			u64 value = *(u64*)arg;
			ITOA16(value,  numArg);
		}
		else if (type & U32) {
			u32 value = *(u32*)arg;
			ITOA16(value,  numArg);
		}
		else if (type & U16) {
			u16 value = *(u16*)arg;
			ITOA16(value,  numArg);
		}
		else if (type & U8)  {
			u8 value = *(u8*)arg;
			ITOA16(value,  numArg);
		}

		__builtin_memcpy(log->arg, numArg, sizeof(log->arg));
	} else if (type & SIGN) {
		char numArg[ARGS_LEN] = {0, };
		type ^= SIGN;
		if (type & S64) {
			u64 value = *(s64*)arg;
			ITOA16(value,  numArg);
		}
		else if (type & S32) {
			u32 value = *(s32*)arg;
			ITOA16(value,  numArg);
		}
		else if (type & S16) {
			u16 value = *(s16*)arg;
			ITOA16(value,  numArg);
		}
		else if (type & S8)  {
			u8 value = *(s8*)arg;
			ITOA16(value,  numArg);
		}

		__builtin_memcpy(log->arg, numArg, sizeof(log->arg));

	} else {
		__builtin_memcpy(log->arg, (char *)arg, sizeof(log->arg));
	}
	log->argLen += 1;
	log->pid = pid;

	if (logtype == LOGMAP) {

		u32 idx = 0; 
		u32 logMapIdx = 0;
		u32 *pIdx  = bpf_map_lookup_elem(&logMapIndex, &idx);
		int ret;

		if (pIdx != NULL) {
			logMapIdx = *pIdx;
		}

		ret = bpf_map_update_elem(&logMap, &logMapIdx, log, BPF_ANY);

		bpf_printk("%d, %u\n", ret, logMapIdx);

		if (ret == 0) {
			logMapIdx++;
			logMapIdx %= LOG_MAX_IDX;
			bpf_map_update_elem(&logMapIndex, &idx, &logMapIdx, BPF_ANY);
		}
	} else if (logtype == LOGPIPE) {
		bpf_printk("[%s][%d]\n", log->func, log->line);
		bpf_printk("\tMessage - %s\n", log->message);
		bpf_printk("\tInfo - %s\n", log->arg);
		bpf_printk("\tPID - %llu\n", pid);
	}


}


#define SET_CONFIG_VAL \
	int configKey = BPF_LOGTYPE;\
	int checkLogType = LOGPIPE; \
	int checkLogLevel = WARN; \
	ConfigValue *pConfig = bpf_map_lookup_elem(&configMap, &configKey);\
	if (pConfig != NULL) {\
		ATOI1(pConfig->str, checkLogType);\
	}\
	configKey = BPF_LOGLEVEL;\
	pConfig = bpf_map_lookup_elem(&configMap, &configKey);\
	if (pConfig != NULL) {\
		ATOI1(pConfig->str, checkLogLevel);\
	}\

#define PROBE_START \
	u64 pid = GET_PID; \
	SET_CONFIG_VAL \
	LOG_PRINTK_ARGS("probe start", (void*)&pid, U64, DEBUG); \

#define PROBE_ERROR \
	LOG_PRINTK("probe error", DEBUG); \
	return BPF_RET_ERROR; \

#define PROBE_END \
	LOG_PRINTK("probe complete", DEBUG); \
	return BPF_RET_OK; \


/////////////////////////////////////////////////////////////////////////////////////////////////

__attribute__((always_inline))
static int setFourTupleKey(FourTupleKey *key, struct sock *sk) {
	SET_CONFIG_VAL;
	short unsigned int family = 0;
	int ret = 0;

	bpf_probe_read_kernel(&family, sizeof(family), &(sk->__sk_common.skc_family));
	if (family == AF_INET) {
		bpf_probe_read_kernel(&key->saddr, sizeof(key->saddr), &(sk->__sk_common.skc_rcv_saddr));
		bpf_probe_read_kernel(&key->daddr, sizeof(key->daddr), &(sk->__sk_common.skc_daddr));
		ret = ETH_P_IP;
		key->ipv = ETH_P_IP;
	} else if (family == AF_INET6){
		bpf_probe_read_kernel(&key->saddrv6, sizeof(key->saddrv6), &(sk->__sk_common.skc_v6_rcv_saddr));
		bpf_probe_read_kernel(&key->daddrv6, sizeof(key->daddrv6), &(sk->__sk_common.skc_v6_daddr));
		ret = ETH_P_IPV6;
		key->ipv = ETH_P_IPV6;
	} else {
		LOG_PRINTK_ARGS("family value error", (void *)&family, U16, INFO);
		return BPF_RET_ERROR;
	}

	bpf_probe_read_kernel(&key->sport, sizeof(key->sport), &(sk->__sk_common.skc_num));
	bpf_probe_read_kernel(&key->dport, sizeof(key->dport), &(sk->__sk_common.skc_dport));
	key->dport = bpf_ntohs(key->dport);

	return ret;
}

__attribute__((always_inline))
static int setProcessSessionKey(ProcessSessionKey *key, struct sock *sk) {
	SET_CONFIG_VAL;
	
	u64 pid = GET_PID;
	key->pid = pid;

	int ret = setFourTupleKey(&key->fourTuple, sk);
	return ret;
}

__attribute__((always_inline))
static int setUDPProcessSessionKey(ProcessSessionKey *key, UdpArgs *args, int ipv) {
	u64 pid = GET_PID;
	int ret = 0;
	key->pid = pid;

	if (ipv == ETH_P_IP) {
		bpf_probe_read_kernel(&key->fourTuple.saddr, sizeof(key->fourTuple.saddr), &(args->fl4->saddr));
		bpf_probe_read_kernel(&key->fourTuple.daddr, sizeof(key->fourTuple.daddr), &(args->fl4->daddr));
		bpf_probe_read_kernel(&key->fourTuple.sport, sizeof(key->fourTuple.sport), &(args->fl4->uli.ports.sport));
		bpf_probe_read_kernel(&key->fourTuple.dport, sizeof(key->fourTuple.dport), &(args->fl4->uli.ports.dport));
		ret = ETH_P_IP;
		key->fourTuple.ipv = ETH_P_IP;

		key->fourTuple.dport = bpf_ntohs(key->fourTuple.dport);
	} else if (ipv == ETH_P_IPV6) {
		bpf_probe_read_kernel(&key->fourTuple.saddrv6, sizeof(key->fourTuple.saddrv6), &(args->fl6->saddr));
		bpf_probe_read_kernel(&key->fourTuple.daddrv6, sizeof(key->fourTuple.daddrv6), &(args->fl6->daddr));
		bpf_probe_read_kernel(&key->fourTuple.sport, sizeof(key->fourTuple.sport), &(args->fl6->uli.ports.sport));
		bpf_probe_read_kernel(&key->fourTuple.dport, sizeof(key->fourTuple.dport), &(args->fl6->uli.ports.dport));
		ret = ETH_P_IPV6;
		key->fourTuple.ipv = ETH_P_IPV6;
	} else {
		return BPF_RET_ERROR;
	}

	key->fourTuple.sport = bpf_ntohs(key->fourTuple.sport);
	key->fourTuple.dport = bpf_ntohs(key->fourTuple.dport);

	return ret;
}

__attribute__((always_inline))
static int closeSessionFunc(ProcessSessionKey *pKey) {
	SET_CONFIG_VAL
	SessionInfo *sInfo = bpf_map_lookup_elem(&sessionInfoMap, &pKey->fourTuple);
	if (sInfo == NULL) {
		LOG_PRINTK("Session info NULL", WARN);
		return BPF_RET_ERROR;
	}

	int i = 0;
	#pragma unroll
	for (i = 0; i < MAX_PID_LIST; i++) {
		bpf_probe_read_kernel(&pKey->pid, sizeof(u32), &sInfo->pid[i]);
		if (pKey->pid == 0) break;

		CloseStateValue dummy;
		__builtin_memset(&dummy, 0, sizeof(CloseStateValue));
		bpf_map_update_elem(&closeStateMap, pKey, &dummy, BPF_NOEXIST);

		CloseStateValue *closeState = bpf_map_lookup_elem(&closeStateMap, pKey);
		if (closeState == NULL) {
			LOG_PRINTK("Close State Value NULL", WARN);
			continue;
		}


		SessionStateValue *sValue = bpf_map_lookup_elem(&sessionStateMap, pKey);
		if (sValue == NULL) {
			LOG_PRINTK("Session State Value NULL", WARN);
			continue;
		}

		closeState->sessionState.ether = sValue->ether;
		closeState->sessionState.direction = sValue->direction;
		closeState->sessionState.protocol = sValue->protocol;
		closeState->sessionState.sendCount += sValue->sendCount;
		closeState->sessionState.recvCount += sValue->recvCount;
		closeState->sessionState.sendByte += sValue->sendByte;
		closeState->sessionState.recvByte += sValue->recvByte;

		bpf_map_delete_elem(&sessionStateMap, pKey);

		if (sValue->protocol == IPPROTO_TCP) {
			TCPStateValue *tcpValue = bpf_map_lookup_elem(&tcpStateMap, pKey);
			if (tcpValue == NULL) {
				LOG_PRINTK("TCP State Value NULL", WARN);
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

			bpf_map_delete_elem(&tcpStateMap, pKey);
		}
	}

	bpf_map_delete_elem(&sessionInfoMap, &pKey->fourTuple);
	return BPF_RET_OK;

}

__attribute__((always_inline))
static void getTCPPacketCount(struct tcp_sock *ts, u32 *sendCount, u32 *recvCount) {
	bpf_probe_read_kernel(sendCount, sizeof(*sendCount), &ts->segs_out);
	bpf_probe_read_kernel(recvCount, sizeof(*recvCount), &ts->segs_in);
}

__attribute__((always_inline))
static int setSessionState(ProcessSessionKey *key,u16 ether, u8 protocol, u8 direction, u32 sendByte, u32 sendCount, u32 recvByte, u32 recvCount) {
	SET_CONFIG_VAL
	SessionStateValue *sValue = bpf_map_lookup_elem(&sessionStateMap, key);
	SessionStateValue dummy;
	__builtin_memset(&dummy, 0, sizeof(SessionStateValue));
	

	//DEBUGING
	LOG_PRINTK_ARGS("ether", (void *)&ether, U8, DEBUG);
	LOG_PRINTK_ARGS("direction", (void *)&direction, U8, DEBUG);
	LOG_PRINTK_ARGS("sendByte", (void *)&sendByte, U32, DEBUG);
	LOG_PRINTK_ARGS("sendCount", (void *)&sendCount, U32, DEBUG);
	LOG_PRINTK_ARGS("recvByte", (void *)&recvByte, U32, DEBUG);
	LOG_PRINTK_ARGS("recvCOunt", (void *)&recvCount, U32, DEBUG);

	//타이밍 문제인지 수집 자체 문제인지 검사
	if (sendByte > 0 && sendCount == 0) {
		LOG_PRINTK("Send : No Count & Set Byte", ERROR);
	}
	if (recvByte > 0 && recvCount == 0) {
		LOG_PRINTK("Recv : No Count & Set Byte", ERROR);
	}

	if (sValue == NULL) { 
		sValue = &dummy;
	}

	if (sValue->direction == UNKNOWN) {
		if (direction == UNKNOWN) {
			u16 *type = bpf_map_lookup_elem(&bindCheckMap, &key->fourTuple.sport);
			if (type != NULL) {
				sValue->direction = IN;
			} else {
				// bindCheckMap에 ebpf 실행전에 bind된 내용이 갱신 되어 있어야함. (외부 Agent에서 처리됨)
				// 해당 부분도 옵션으로 제공
				//TODO Agent 부분 개발 완료 후 주석 헤제
				if (protocol == IPPROTO_TCP) {
					sValue->direction = OUT; 
				}
			}
		} else {
			sValue->direction = direction;
		}
	}

	sValue->ether = ether;
	sValue->protocol = protocol;
	if (protocol == IPPROTO_TCP) {
		if (sValue->sendCount < sendCount) {
			sValue->sendCount = sendCount;
		}
		if (sValue->recvCount < recvCount) {
			sValue->recvCount = recvCount;
		}
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
	SET_CONFIG_VAL
	TCPStateValue dummy;
	__builtin_memset(&dummy, 0, sizeof(TCPStateValue));
	bpf_map_update_elem(&tcpStateMap, key, &dummy, BPF_NOEXIST);

	TCPStateValue *tcpValue = bpf_map_lookup_elem(&tcpStateMap, key);
	if (tcpValue == NULL) {
		LOG_PRINTK("TCP MAP Value Null", WARN);
		return BPF_RET_ERROR;
	}

	u32 tSrtt;
	u32 tMdev;

	bpf_probe_read_kernel(&tSrtt, sizeof(tSrtt), &ts->srtt_us);
	bpf_probe_read_kernel(&tMdev, sizeof(tMdev), &ts->mdev_us);

	//https://elixir.bootlin.com/linux/v4.6/source/net/ipv4/tcp.c#L2686
	tSrtt = tSrtt >> 3;
	tMdev = tMdev >> 2;

	//DEBUGING
	if (tSrtt == 0) {
		LOG_PRINTK_ARGS("Latency Value Error", (void *)&tSrtt, U32, ERROR);
	}
	if (tMdev == 2500000) {
		LOG_PRINTK_ARGS("Jitter Value ERROR", (void *)&tMdev, U32, ERROR);
	}
	if (tSrtt == 0 && tMdev == 2500000) {
		LOG_PRINTK("Latency&Jitter, Return Error", ERROR);
		return BPF_RET_ERROR;
	}


	tcpValue->latency = tSrtt;
	tcpValue->jitter = tMdev;

	//tcpValue->state |= (1 << state);

	u32 lostCount;
	u32 retransCount;

	bpf_probe_read_kernel(&lostCount, sizeof(lostCount), &ts->lost_out);
	bpf_probe_read_kernel(&retransCount, sizeof(retransCount), &ts->retrans_out);

	if (lostCount > 0)
		__sync_fetch_and_add(&tcpValue->lostCount, lostCount);
	if (retransCount > 0)
		__sync_fetch_and_add(&tcpValue->retransCount, retransCount);

	LOG_PRINTK_ARGS("Lost Count", (void *)&lostCount, U32, DEBUG);
	LOG_PRINTK_ARGS("Retrans Count", (void *)&retransCount, U32, DEBUG);


	return BPF_RET_OK;
}

__attribute__((always_inline))
static int setSessionInfo(FourTupleKey *key, u16 state, u32 pid) {
	SET_CONFIG_VAL
	SessionInfo dummy;
	__builtin_memset(&dummy, 0, sizeof(SessionInfo));
	bpf_map_update_elem(&sessionInfoMap, key, &dummy, BPF_NOEXIST);


	SessionInfo *sInfo = bpf_map_lookup_elem(&sessionInfoMap, key);
	if (sInfo == NULL) {
		LOG_PRINTK("Session Info NULL", WARN)
		return BPF_RET_ERROR;
	}

	if (state != NOT_USE) {
		sInfo->state |= (1 << state);
	}

	int i = 0;
	int check = 0;
	#pragma unroll
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

//
//Common
//TODO : raw_socket 추가 여부는 검토 필요
//현재는 TCP/UDP에 대한 추적으로 제한

//IP Layer
SEC("kprobe/inet_bind")
int kprobe__inet_bind(struct pt_regs *ctx) {
	PROBE_START;

	struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
	struct sockaddr_in *addr = (struct sockaddr_in *)PT_REGS_PARM2(ctx);

	if (sock == NULL || addr == NULL) {
		LOG_PRINTK("sock or addr null", WARN);
		PROBE_ERROR;
	}

	u16 type = 0;

	bpf_probe_read_kernel(&type, sizeof(type), &sock->type);
	
	// TCP는inet_csk_accept 에서 처리하도록 통일?
	if ((type & (SOCK_STREAM|SOCK_DGRAM)) == 0) {
		LOG_PRINTK_ARGS("socket type error", (void *)&type, U16, INFO);
		PROBE_ERROR;
	}

	u16 sin_port = 0;
	bpf_probe_read_kernel(&sin_port, sizeof(u16), &(addr->sin_port));
	sin_port = bpf_ntohs(sin_port);
	
	if (sin_port == 0) {
		LOG_PRINTK("bind port zero", WARN);
		PROBE_ERROR;

	}

	bpf_map_update_elem(&bindCheckMap, &sin_port, &type, BPF_NOEXIST);
	
	PROBE_END;
}


SEC("kprobe/inet6_bind")
int kprobe__inet6_bind(struct pt_regs *ctx) {
	PROBE_START;

	struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *)PT_REGS_PARM2(ctx);

	if (sock == NULL || addr == NULL) {
		LOG_PRINTK("sock or addr null", WARN);
		PROBE_ERROR;
	}

	u16 type = 0;
	bpf_probe_read_kernel(&type, sizeof(type), &sock->type);
	if ((type & (SOCK_STREAM|SOCK_DGRAM)) == 0) {
		LOG_PRINTK_ARGS("socket type error", (void *)&type, U16, INFO);
		PROBE_ERROR;
	}

	u16 sin_port = 0;
	bpf_probe_read_kernel(&sin_port, sizeof(u16), &(addr->sin6_port));
	sin_port = bpf_ntohs(sin_port);
	
	if (sin_port == 0) {
		LOG_PRINTK("bind port zero", WARN);
		PROBE_ERROR;
	}


	bpf_map_update_elem(&bindCheckMap, &sin_port, &type, BPF_NOEXIST);
	
	PROBE_END;
}

SEC("kprobe/ip_make_skb")
int kprobe__ip_make_skb(struct pt_regs *ctx) {
	PROBE_START;

	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	int len = PT_REGS_PARM5(ctx);
	struct flowi4 *fl4 = (struct flowi4 *)PT_REGS_PARM2(ctx);

	u16 proto = 0;
	bpf_probe_read_kernel(&proto, sizeof(proto), &sk->sk_protocol);
	u16 type = 0;
	bpf_probe_read_kernel(&type, sizeof(type), &sk->sk_type);
	proto = bpf_ntohs(proto);
	type = bpf_ntohs(type);

	if ((type & IPPROTO_UDP) == 0 && (proto & IPPROTO_UDP) == 0 ) {
		LOG_PRINTK_ARGS("socket type error", (void *)&type, U16, INFO);
		PROBE_ERROR;
	}

	UdpArgs udpArgs = {};
	ProcessSessionKey key;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));

	bpf_probe_read_kernel(&udpArgs.sk, sizeof(udpArgs.sk), &sk);
	bpf_probe_read_kernel(&udpArgs.len, sizeof(udpArgs.len), &len);
	bpf_probe_read_kernel(&udpArgs.fl4, sizeof(udpArgs.fl4), &fl4);
	setUDPProcessSessionKey(&key, &udpArgs, ETH_P_IP);

	bpf_map_update_elem(&udpSendSock, &pid, &key, BPF_ANY);

	PROBE_END;
}

SEC("kprobe/ip6_make_skb")
int kprobe__ip6_make_skb(struct pt_regs *ctx) {
	PROBE_START;

	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	int len = PT_REGS_PARM5(ctx);
	struct flowi6 *fl6 = (struct flowi6 *)PT_REGS_PARM7(ctx);

	u16 proto = 0;
	bpf_probe_read_kernel(&proto, sizeof(proto), &sk->sk_protocol);
	u16 type = 0;
	bpf_probe_read_kernel(&type, sizeof(type), &sk->sk_type);
	proto = bpf_ntohs(proto);
	type = bpf_ntohs(type);

	if ((type & IPPROTO_UDP) == 0 && (proto & IPPROTO_UDP) == 0 ) {
		LOG_PRINTK_ARGS("socket type error", (void *)&type, U16, INFO);
		PROBE_ERROR;
	}

	UdpArgs udpArgs = {};
	ProcessSessionKey key;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));

	bpf_probe_read_kernel(&udpArgs.sk, sizeof(udpArgs.sk), &sk);
	bpf_probe_read_kernel(&udpArgs.len, sizeof(udpArgs.len), &len);
	bpf_probe_read_kernel(&udpArgs.fl6, sizeof(udpArgs.fl6), &fl6);
	setUDPProcessSessionKey(&key, &udpArgs, ETH_P_IPV6);

	bpf_map_update_elem(&udpSendSock, &pid, &key, BPF_ANY);

	PROBE_END;
}

SEC("kretprobe/ip6_make_skb")
int kretprobe__ip6_make_skb(struct pt_regs *ctx) {
	PROBE_START;
	PROBE_END;
}

SEC("kretprobe/ip_make_skb")
int kretprobe__ip_make_skb(struct pt_regs *ctx) {
	PROBE_START;
	PROBE_END;
}

SEC("kprobe/inet_release")
int kprobe__inet_release(struct pt_regs *ctx) {
	PROBE_START;
	PROBE_END;
}

SEC("kprobe/inet6_release")
int kprobe__inet6_release(struct pt_regs *ctx) {
	PROBE_START;
	PROBE_END;
}

///
// TCP

SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs* ctx) {
	PROBE_START;
	struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
	if (sk == NULL) {
		LOG_PRINTK("struct sock is Null", WARN);
		PROBE_ERROR;
	}

	ProcessSessionKey key;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if (setProcessSessionKey(&key, sk) == BPF_RET_ERROR) {
		LOG_PRINTK("Set Session Key Fail", WARN);
		PROBE_ERROR;
	}

	// BIND 없이 진행되는 케이스 존재
	u16 type = SOCK_STREAM;
	bpf_map_update_elem(&bindCheckMap, &key.fourTuple.sport, &type, BPF_NOEXIST);

	int ret = setSessionInfo(&key.fourTuple, TCP_ESTABLISHED, key.pid);
	if (ret != BPF_RET_OK) {
		LOG_PRINTK("Set Seeion Info Fail", WARN);
		PROBE_ERROR;
	}

	PROBE_END;
}

SEC("kprobe/tcp_connect")
int kprobe__tcp_connect(struct pt_regs *ctx) {
	PROBE_START;

	struct sock *sk;

	sk = (struct sock *) PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&connectSock, &pid, &sk, BPF_ANY);

	PROBE_END;
}

SEC("kretprobe/tcp_connect")
int kretprobe__tcp_connect(struct pt_regs *ctx) {
	PROBE_START;

	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&connectSock, &pid);
	if (skpp == NULL) {
		LOG_PRINTK("connectsock data is Null", WARN);
		PROBE_ERROR;
	}

	struct sock *sk = *skpp;
	bpf_map_delete_elem(&connectSock, &pid);
	int ret = PT_REGS_RC(ctx);
	if (ret != 0) {
		LOG_PRINTK("tcp_connect ret error", WARN);
		PROBE_ERROR;
	}

	ProcessSessionKey key;
	int ipv;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if ((ipv = setProcessSessionKey(&key, sk)) == BPF_RET_ERROR) {
		LOG_PRINTK("Set ProcessSessionKey Fail", WARN);
		PROBE_ERROR;
	}

	u8 state = TCP_SYN_SENT;
	ret = setSessionInfo(&key.fourTuple, state, key.pid);
	if (ret != BPF_RET_OK) {
		LOG_PRINTK("Set SessionInfo Fail", WARN);
		PROBE_ERROR;
	}

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	if (ts == NULL) {
		LOG_PRINTK("tcp_sock is Null", WARN);
		PROBE_ERROR;
	}

	if ((ret = setSessionState(&key, ipv, IPPROTO_TCP, OUT, 0, 0, 0, 0)) != BPF_RET_OK) {
		LOG_PRINTK("Set TCP SessionState Fail", INFO);
		PROBE_ERROR;
	}


	if (setTCPState(&key, ts) == BPF_RET_ERROR) {
		LOG_PRINTK("Set TCP State Fail", WARN);
		PROBE_ERROR;
	}

	PROBE_END;
}


SEC("kprobe/tcp_finish_connect")
int kprobe__tcp_finish_connect(struct pt_regs* ctx) {
	PROBE_START;

	struct sock *sk;
	sk = (struct sock *) PT_REGS_PARM1(ctx);
	if (sk == NULL) {
		LOG_PRINTK("sock is Null", WARN);
		PROBE_ERROR;
	}

	ProcessSessionKey key;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if (setProcessSessionKey(&key, sk) == BPF_RET_ERROR) {
		LOG_PRINTK("Set ProcessSessionKey Fail", WARN);
		PROBE_ERROR;
	}

	u8 state = TCP_ESTABLISHED;
	int ret = setSessionInfo(&key.fourTuple, state, key.pid);
	if (ret != BPF_RET_OK) {
		LOG_PRINTK("Set SessionInfo Fail", WARN);
		PROBE_ERROR;
	}

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	if (setTCPState(&key, ts) == BPF_RET_ERROR) {
		LOG_PRINTK("Set TCP State Fail", WARN);
		PROBE_ERROR;
	}

	PROBE_END;
}

SEC("kprobe/tcp_set_state")
int kprobe__tcp_set_state(struct pt_regs* ctx) {
	PROBE_START;

	struct sock *sk;
	sk = (struct sock *) PT_REGS_PARM1(ctx);
	if (sk == NULL) {
		LOG_PRINTK("sock is Null", WARN);
		PROBE_ERROR;
	}

	u32 state;
	state = PT_REGS_PARM2(ctx);

	if (state != TCP_ESTABLISHED || state != TCP_CLOSE) {
		LOG_PRINTK_ARGS("TCP State error", (void *)&state, U32, INFO);
		PROBE_ERROR;
	}

	ProcessSessionKey key;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if (setProcessSessionKey(&key, sk) == BPF_RET_ERROR) {
		LOG_PRINTK("Set ProcessSessionKey Fail", WARN);
		PROBE_ERROR;
	}

	int ret = setSessionInfo(&key.fourTuple, state, key.pid);
	if (ret != BPF_RET_OK) {
		LOG_PRINTK("Set SessionInfo Fail", WARN);
		PROBE_ERROR;
	}

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	if (setTCPState(&key, ts) == BPF_RET_ERROR) {
		LOG_PRINTK("Set TCP State Fail", WARN);
		PROBE_ERROR;
	}

	PROBE_END;
}


SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs*ctx) {
	PROBE_START;

	struct sock *sk;

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&sendSock, &pid, &sk, BPF_ANY);

	PROBE_END;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe__tcp_sendmsg(struct pt_regs*ctx) {
	PROBE_START;

	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&sendSock, &pid);
	if (skpp == NULL) {
		LOG_PRINTK("sendsock data is Null", WARN);
		PROBE_ERROR;
	}
	bpf_map_delete_elem(&sendSock, &pid);

	struct sock *sk = *skpp;
	if (sk == NULL) {
		LOG_PRINTK("sock is Null", WARN);
		PROBE_ERROR;
	}

	int sendByte = PT_REGS_RC(ctx);
	if (sendByte < 0) {
		LOG_PRINTK("send ret error", WARN);
		PROBE_ERROR;
	}
	int recvByte = 0;

	ProcessSessionKey key;
	int ipv;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if ((ipv = setProcessSessionKey(&key, sk)) == BPF_RET_ERROR) {
		LOG_PRINTK("Set ProcessSessionKey Fail", WARN);
		PROBE_ERROR;
	}

	u8 state = TCP_ESTABLISHED;
	int ret = setSessionInfo(&key.fourTuple, state, key.pid);
	if (ret != BPF_RET_OK) {
		LOG_PRINTK("Set SessionInfo Fail", WARN);
		PROBE_ERROR;
	}

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	if (ts == NULL) {
		LOG_PRINTK("tcp_sock is Null", WARN);
		PROBE_ERROR;
	}
	u32 sendCount;
	u32 recvCount;

	getTCPPacketCount(ts, &sendCount, &recvCount);
	if ((sendCount <= (u32)0 && recvCount <= (u32)0) || sendCount == (u32)-1 || recvCount == (u32)-1) {
		LOG_PRINTK_ARGS("Packet Count Error, sendcount", (void *)&sendCount, U32, WARN);
		LOG_PRINTK_ARGS("Packet Count Error, recvcount", (void *)&recvCount, U32, WARN);
		PROBE_ERROR;
	}

	if ((ret = setSessionState(&key, ipv, IPPROTO_TCP, UNKNOWN, sendByte, sendCount, recvByte, recvCount)) != BPF_RET_OK) {
		LOG_PRINTK("Set TCP SessionState Fail", INFO);
		PROBE_ERROR;
	}

	if (setTCPState(&key, ts) == BPF_RET_ERROR) {
		LOG_PRINTK("Set TCP State Fail", INFO);
		PROBE_ERROR;
	}

	PROBE_END;
}

SEC("kprobe/tcp_recvmsg")
int kprobe__tcp_recvmsg(struct pt_regs *ctx) {
	PROBE_START;

	struct sock*sk;
	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&recvSock, &pid, &sk, BPF_ANY);

	PROBE_END;
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe__tcp_recvmsg(struct pt_regs *ctx) {
	PROBE_START;
	
	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&recvSock, &pid);
	if (skpp == NULL) {
		LOG_PRINTK("recvsock data is Null", WARN);
		PROBE_ERROR;
	}
	bpf_map_delete_elem(&recvSock, &pid);

	struct sock *sk = *skpp;
	if (sk == NULL) {
		LOG_PRINTK("sock is Null", WARN);
		PROBE_ERROR;
	}
	
	int recvByte = PT_REGS_RC(ctx);
	if (recvByte < 0 ) {
		LOG_PRINTK("recv ret error", WARN);
		PROBE_ERROR;
	}

	LOG_PRINTK_ARGS("recv ", (void *)&recvByte, S32, DEBUG);
	int sendByte = 0;

	ProcessSessionKey key;
	int ipv;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if ((ipv = setProcessSessionKey(&key, sk)) == BPF_RET_ERROR) {
		LOG_PRINTK("Set ProcessSessionKey Fail", WARN);
		PROBE_ERROR;
	}

	u8 state = TCP_ESTABLISHED;
	int ret = setSessionInfo(&key.fourTuple, state, key.pid);
	if (ret != BPF_RET_OK) {
		LOG_PRINTK("Set SessionInfo Fail", WARN);
		PROBE_ERROR;
	}

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	if (ts == NULL) {
		LOG_PRINTK("tcp_sock is Null", WARN);
		PROBE_ERROR;
	}

	u32 sendCount;
	u32 recvCount;

	getTCPPacketCount(ts, &sendCount, &recvCount);
	if ((sendCount <= (u32)0 && recvCount <= (u32)0) || sendCount == (u32)-1 || recvCount == (u32)-1) {
		LOG_PRINTK_ARGS("Packet Count Error, sendcount", (void *)&sendCount, U32, WARN);
		LOG_PRINTK_ARGS("Packet Count Error, recvcount", (void *)&recvCount, U32, WARN);
		PROBE_ERROR;
	}

	if ((ret = setSessionState(&key, ipv, IPPROTO_TCP, UNKNOWN, sendByte, sendCount, recvByte, recvCount)) != BPF_RET_OK) {
		LOG_PRINTK("Set TCP SessionState Fail", INFO);
		PROBE_ERROR;
	}

	if (setTCPState(&key, ts) == BPF_RET_ERROR) {
		LOG_PRINTK("Set TCP State Fail", INFO);
		PROBE_ERROR;
	}

	PROBE_END;
}

/*
 * tcp_recvmsg로 대체
 
SEC("kprobe/tcp_cleanup_rbuf")
int kprobe__tcp__cleanup_rbpf(struct pt_regs *ctx) {
	PROBE_START;

	struct sock *sk;

	sk = (struct sock *) PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&recvSock, &pid, &sk, BPF_ANY);

	PROBE_END;
}

SEC("kretprobe/tcp_cleanup_rbuf")
int kretprobe__tcp__cleanup_rbpf(struct pt_regs *ctx) {
	PROBE_START;


	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&recvSock, &pid);
	if (skpp == NULL) {
		LOG_PRINTK("recvsock data is Null", WARN);
		PROBE_ERROR;
	}
	bpf_map_delete_elem(&recvSock, &pid);

	struct sock *sk = *skpp;
	if (sk == NULL) {
		LOG_PRINTK("sock is Null", WARN);
		PROBE_ERROR;
	}
	
	int recvByte = PT_REGS_PARM2(ctx);
	if (recvByte < 0) {
		LOG_PRINTK("recv ret error", WARN);
		LOG_PRINTK_ARGS("recv ret error", (void *)&recvByte, S32, WARN);
		PROBE_ERROR;
	}
	LOG_PRINTK_ARGS("cleanup ", (void *)&recvByte, S32, WARN);
	int sendByte = 0;

	ProcessSessionKey key;
	int ipv;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if ((ipv = setProcessSessionKey(&key, sk)) == BPF_RET_ERROR) {
		LOG_PRINTK("Set ProcessSessionKey Fail", WARN);
		PROBE_ERROR;
	}

	u8 state = TCP_ESTABLISHED;
	int ret = setSessionInfo(&key.fourTuple, state, key.pid);
	if (ret != BPF_RET_OK) {
		LOG_PRINTK("Set SessionInfo Fail", WARN);
		PROBE_ERROR;
	}

	struct tcp_sock *ts = (struct tcp_sock*)sk;
	if (ts == NULL) {
		LOG_PRINTK("tcp_sock is Null", WARN);
		PROBE_ERROR;
	}

	u32 sendCount;
	u32 recvCount;

	getTCPPacketCount(ts, &sendCount, &recvCount);
	if ((sendCount <= (u32)0 && recvCount <= (u32)0) || sendCount == (u32)-1 || recvCount == (u32)-1) {
		LOG_PRINTK_ARGS("Packet Count Error, sendcount", (void *)&sendCount, U32, WARN);
		LOG_PRINTK_ARGS("Packet Count Error, recvcount", (void *)&recvCount, U32, WARN);
		PROBE_ERROR;
	}

	if ((ret = setSessionState(&key, ipv, IPPROTO_TCP, UNKNOWN, sendByte, sendCount, recvByte, recvCount)) != BPF_RET_OK) {
		LOG_PRINTK("Set TCP SessionState Fail", INFO);
		PROBE_ERROR;
	}

	if (setTCPState(&key, ts) == BPF_RET_ERROR) {
		LOG_PRINTK("Set TCP State Fail", INFO);
		PROBE_ERROR;
	}

	PROBE_END;
}
*/

SEC("kprobe/tcp_close")
int kprobe__tcp_close(struct pt_regs *ctx) {
	PROBE_START;

	struct sock *sk;
	sk = (struct sock *) PT_REGS_PARM1(ctx);
	if (sk == NULL) {
		LOG_PRINTK("sock is Null", WARN);
		PROBE_ERROR;
	}

	ProcessSessionKey key;
	int ipv;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));
	if ((ipv = setProcessSessionKey(&key, sk)) == BPF_RET_ERROR) {
		LOG_PRINTK("Set ProcessSessionKey Fail", WARN);
		PROBE_ERROR;
	}
	
	closeSessionFunc(&key);

	PROBE_END;
}

SEC("kprobe/inet_csk_listen_stop")
int kprobe__inet_csk_listen_stop(struct pt_regs *ctx) {
	PROBE_START;

	struct sock *sk;
	sk = (struct sock *) PT_REGS_PARM1(ctx);
	if (sk == NULL) {
		LOG_PRINTK("sock is Null", WARN);
		PROBE_ERROR;
	}

	u16 sport;
	bpf_probe_read_kernel(&sport, sizeof(sport), &(sk->__sk_common.skc_num));

	bpf_map_delete_elem(&bindCheckMap, &sport);

	PROBE_END;
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
#endif





///
// UDP
SEC("kprobe/udpv6_sendmsg")
int kprobe__udpv6_sendmsg(struct pt_regs *ctx) {
	PROBE_START;
	PROBE_END;
}

SEC("kprobe/udp_sendmsg")
int kprobe__udp_sendmsg(struct pt_regs *ctx) {
	PROBE_START;
	PROBE_END;
}

__attribute__((always_inline))
static int udp_sendmsg_func(struct pt_regs *ctx) {
	PROBE_START;

	ProcessSessionKey *key;
	key = bpf_map_lookup_elem(&udpSendSock, &pid);
	if (key == NULL) {
		LOG_PRINTK("udpsendSock data is Null", WARN);
		PROBE_ERROR;
	}


	int sendByte = PT_REGS_RC(ctx);
	if (sendByte < 0) {
		LOG_PRINTK("send ret error", WARN);
		PROBE_ERROR;
	}
	int recvByte = 0;

	ProcessSessionKey pKey;
	__builtin_memset(&pKey, 0, sizeof(ProcessSessionKey));

	bpf_probe_read_kernel(&pKey, sizeof(pKey), key);

	int ret = setSessionInfo(&pKey.fourTuple, NOT_USE, pKey.pid);
	if (ret != BPF_RET_OK) {
		LOG_PRINTK("Set SessionInfo Fail", WARN);
		PROBE_ERROR;
	}

	if ((ret = setSessionState(&pKey, pKey.fourTuple.ipv, IPPROTO_UDP, UNKNOWN, sendByte, 1, recvByte, 0)) != BPF_RET_OK) {
		LOG_PRINTK("Set UDP SessionState Fail", INFO);
		PROBE_ERROR;
	}

	PROBE_END;
}

SEC("kretprobe/udpv6_sendmsg")
int kretprobe__udpv6_sendmsg(struct pt_regs*ctx) {
	return udp_sendmsg_func(ctx);
}


SEC("kretprobe/udp_sendmsg")
int kretprobe__udp_sendmsg(struct pt_regs*ctx) {
	return udp_sendmsg_func(ctx);
}

SEC("kprobe/udpv6_recvmsg")
int kprobe__udpv6_recvmsg(struct pt_regs *ctx) {
	PROBE_START;
	PROBE_END;
}

SEC("kprobe/udp_recvmsg")
int kprobe__udp_recvmsg(struct pt_regs *ctx) {
	PROBE_START;
	PROBE_END;
}

__attribute__((always_inline))
static int udp_recvmsg_func(struct pt_regs *ctx) {
	PROBE_START;

	ProcessSessionKey *key;
	key = bpf_map_lookup_elem(&udpRecvSock, &pid);
	if (key == NULL) {
		LOG_PRINTK("udprecvSock data is Null", WARN);
		PROBE_ERROR;
	}
	int len = PT_REGS_PARM3(ctx);
	int recvByte = PT_REGS_RC(ctx);
	if (recvByte < 0) {
		LOG_PRINTK("recv ret error", WARN);
		PROBE_ERROR;
	}
	int sendByte = 0;

	int ret = setSessionInfo(&key->fourTuple, NOT_USE, key->pid);
	if (ret != BPF_RET_OK) {
		LOG_PRINTK("Set SessionInfo Fail", WARN);
		PROBE_ERROR;
	}

	if ((ret = setSessionState(key, key->fourTuple.ipv, IPPROTO_UDP, UNKNOWN, sendByte, 0, recvByte, 1)) != BPF_RET_OK) {
		LOG_PRINTK("Set UDP SessionState Fail", INFO);
		PROBE_ERROR;
		return BPF_RET_ERROR;
	}

	PROBE_END;
}

SEC("kretprobe/udpv6_recvmsg")
int kretprobe_udpv6_recvmsg(struct pt_regs *ctx) {
	return udp_recvmsg_func(ctx);

}

SEC("kretprobe/udp_recvmsg")
int kretprobe_udp_recvmsg(struct pt_regs *ctx) {
	return udp_recvmsg_func(ctx);
}

//TODO
//sk_buff 관련 부분은 udp에서 4tuple 획득 말고도 여러 raw데이터 뽑는 형태로 활용 가능
//추후 common 로직으로 분리 필요

SEC("kprobe/skb_consume_udp")
int kprobe__skb_consume_udp(struct pt_regs *ctx) {
	PROBE_START;

	struct sock *sk;
	sk = (struct sock*) PT_REGS_PARM1(ctx);
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
	
	unsigned char *head;
	bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
	u16 network_header;
	bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
	struct iphdr iph;

	bpf_probe_read_kernel(&iph, sizeof(iph), (struct iphdr *)(head + network_header));

	ProcessSessionKey key;
	__builtin_memset(&key, 0, sizeof(ProcessSessionKey));

	int ret = 0;
	key.pid = pid;

	if (iph.version == 4) {
		key.fourTuple.saddr = iph.daddr;
		key.fourTuple.daddr = iph.saddr;
		key.fourTuple.ipv = ETH_P_IP;
	} else if (iph.version == 6) {
		struct ipv6hdr ip6h;
		__builtin_memset(&ip6h, 0, sizeof(ip6h));
		bpf_probe_read_kernel(&ip6h, sizeof(ip6h), (struct ipv6hdr *)(head + network_header));
		__builtin_memcpy(&key.fourTuple.saddrv6, &ip6h.daddr, sizeof(key.fourTuple.saddrv6));
		__builtin_memcpy(&key.fourTuple.daddrv6, &ip6h.saddr, sizeof(key.fourTuple.daddrv6));
		key.fourTuple.ipv = ETH_P_IPV6;
	}


	u16 transport_header;
	bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);
	
	struct udphdr udph;
	bpf_probe_read_kernel(&udph, sizeof(udph), (struct udphdr *)(head + transport_header));


	bpf_probe_read_kernel(&key.fourTuple.sport, sizeof(key.fourTuple.sport), &udph.dest);
	bpf_probe_read_kernel(&key.fourTuple.dport, sizeof(key.fourTuple.dport), &udph.source);
	key.fourTuple.sport = bpf_ntohs(key.fourTuple.sport);
	key.fourTuple.dport = bpf_ntohs(key.fourTuple.dport);


	bpf_map_update_elem(&udpRecvSock, &pid, &key, BPF_ANY);

	PROBE_END;
}

SEC("kretprobe/skb_consume_udp")
int kretprobe__skb_consume_udp(struct pt_regs *ctx) {
	PROBE_START;
	PROBE_END;
}

//TODO fork 에 취약한 형태임
//개선 방법 검토 필요

__attribute__((always_inline))
static int udp_destroy_sock_func(struct pt_regs *ctx) {
	PROBE_START;

	ProcessSessionKey *key;
	key = bpf_map_lookup_elem(&udpSendSock, &pid);
	if (key == NULL) {
		LOG_PRINTK("udpsendSock data is Null", WARN);
		PROBE_ERROR;
	}

	ProcessSessionKey pKey;
	__builtin_memset(&pKey, 0, sizeof(ProcessSessionKey));
	bpf_probe_read_kernel(&pKey, sizeof(pKey), key);

	bpf_map_delete_elem(&udpSendSock, &pid);
	bpf_map_delete_elem(&bindCheckMap, &pKey.fourTuple.sport);
	closeSessionFunc(&pKey);

	key = bpf_map_lookup_elem(&udpRecvSock, &pid);
	if (key == NULL) {
		LOG_PRINTK("udprecvSock data is Null", WARN);
		PROBE_ERROR;
	}
	__builtin_memset(&pKey, 0, sizeof(ProcessSessionKey));
	bpf_probe_read_kernel(&pKey, sizeof(pKey), key);

	bpf_map_delete_elem(&udpRecvSock, &pid);
	bpf_map_delete_elem(&bindCheckMap, &pKey.fourTuple.sport);
	closeSessionFunc(&pKey);


	return BPF_RET_OK;


}

SEC("kprobe/udpv6_destroy_sock")
int kprobe__udpv6_destroy_sock(struct pt_regs *ctx){
	return udp_destroy_sock_func(ctx);
}

SEC("kprobe/udp_destroy_sock")
int kprobe__udp_destroy_sock(struct pt_regs *ctx) {
	return udp_destroy_sock_func(ctx);
}


