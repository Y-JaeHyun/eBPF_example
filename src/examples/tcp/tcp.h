#ifndef __TCP_H__
#define __TCP_H__


#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"

// LICENSE //

char __license[] SEC("license") = "GPL";

// MAP STRUCT //

typedef struct fourTupleKey {
	u16 sport;
	u16 dport;

	// union(addr + addrv6) 사용시 ipv6 정보가 누락되는 현상 있음
	u32 saddr;
	u32 daddr;
	struct in6_addr saddrv6;
	struct in6_addr daddrv6;
	int ipv;
}FourTupleKey;

#define NOCHECK_BIND 0
#define BIND 1
#define NOT_BIND 2

#define NOCHECK_START_SESSION 0
#define START_SESSION 1
#define NOT_START_SESSION 2


typedef struct bindCheckValue {
	u8 bindState;
}BindCheckValue;


typedef struct processSessionKey {
	FourTupleKey fourTuple;
	u32 pid;
}ProcessSessionKey;

#define UNKNOWN 0
#define IN 1
#define OUT 2

//나머지 미지원
#define ETH_P_IP 0x8000
#define ETH_P_IPV6 0x86DD

#define MAX_PID_LIST 5

#define NOT_USE 65535 // u16 -1

typedef struct sessionInfo {
	u16 state;
	u32 pid[MAX_PID_LIST];
	u8 bindState;
	u8 startSession;
}SessionInfo;

typedef struct sessionStateValue {
	u16 ether;
	u8 direction;
	u8 protocol;
	u32 sendCount;
	u32 recvCount;
	u64 sendByte;
	u64 recvByte;
}SessionStateValue;


typedef struct tcpStateValue {
	u32 retransCount;
	u32 lostCount;
	u32 latency;
	u32 jitter;
	//u16 state;
}TCPStateValue;

#define SESSION_INFO 1
#define TCP_INFO 2
typedef struct closeStateValue {
	SessionStateValue sessionState;
	TCPStateValue tcpState;
}CloseStateValue;


typedef struct udp_args {
	struct sock *sk;
	int len;
	struct flowi4 *fl4;
	struct flowi6 *fl6;
}UdpArgs;



struct forTupleKey *unused_four_tuple_key_t  __attribute__((unused));
struct bindCheckValue *unused_bind_Check_value_t  __attribute__((unused));

struct processSessionKey *unused_process_session_key_t  __attribute__((unused));
struct sessionStateValue *unused_session_statue_value_t  __attribute__((unused));
struct tcpStateValue *unused_tcp_state_value_t  __attribute__((unused));
struct closeStateValue *unused_close_state_value_t  __attribute__((unused));



// MAP //



// Key : bind port, Value : Socket Type
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u16));
	__uint(value_size, sizeof(u16));
	__uint(max_entries, 1024);
} bindCheckMap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(FourTupleKey));
	__uint(value_size, sizeof(SessionInfo));
	__uint(max_entries, 1024);
} sessionInfoMap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(ProcessSessionKey));
	__uint(value_size, sizeof(SessionStateValue));
	__uint(max_entries, 1024);
} sessionStateMap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(ProcessSessionKey));
	__uint(value_size, sizeof(TCPStateValue));
	__uint(max_entries, 1024);
} tcpStateMap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(ProcessSessionKey));
	__uint(value_size, sizeof(CloseStateValue));
	__uint(max_entries, 1024);
} closeStateMap SEC(".maps");


#define CONFIG_NAME_LEN 32
#define CONFIG_VALUE_LEN 32

typedef struct configValue {
	char str [CONFIG_VALUE_LEN];
}ConfigValue;

typedef enum {
	BPF_LOGTYPE = 1,
	BPF_LOGLEVEL= 2
}ConfigKey;


struct configValue *unused_config_value_t __attribute__((unused));

ConfigKey *unused_config_key_t __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	//__uint(key_size, sizeof(ConfigName));
	__uint(key_size, sizeof(ConfigKey));
	__uint(value_size, sizeof(ConfigValue));
	__uint(max_entries, 128);
} configMap SEC(".maps");


#define LOG_MESSAGE_LEN 128
#define MAX_NAME_LEN 32
#define ARGS_LEN 16

typedef struct logMessage{
	int level;
	char func[MAX_NAME_LEN];
	u16 line;
	char message[LOG_MESSAGE_LEN];
	char arg[ARGS_LEN];
	char argLen;  // TODO N개 처리 추가
	u64 pid;
}LogMessage;

struct logMessage *unused_log_message_t  __attribute__((unused));

/*
 *kernel 5.x 이상만 사용가능, ARRAY로 대체 구현
 *
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(key_size, 0);
	__uint(value_size, sizeof(LogMessage));
	__uint(max_entries, 512);
} logMap SEC(".maps");
*/

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} logMapIndex SEC(".maps");

#define LOG_MAX_IDX 2048
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(LogMessage));
	__uint(max_entries, LOG_MAX_IDX);
} logMap SEC(".maps");
// ETC //


enum {
	BPF_RET_ERROR = -1,
	BPF_RET_OK = 0,
	BPF_RET_UNKNOWN = 1,
};

#endif //__TCP_H__
