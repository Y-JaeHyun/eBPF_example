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
	union {
		u32 saddr;
		u8 saddrv6[16];
	}sip;
	union {
		u32 daddr;
		u8 daddrv6[16];
	}dip;
	u8 ipv;
}FourTupleKey;

#define NOT_BIND 0
#define BIND 1
typedef struct bindCheckValue {
	u8 bindState;
}BindCheckValue;


typedef struct processSessionKey {
	/*u16 sport;
	u16 dport;
	union {
		u32 saddr;
		u8 saddrv6[16];
	}sip;
	union {
		u32 daddr;
		u8 daddrv6[16];
	}dip;*/
	FourTupleKey fourTuple;
	u32 pid;
}ProcessSessionKey;

#define UNKNOWN 0
#define IN 1
#define OUT 2

//나머지 미지원
#define ETH_P_IP 0x8000
#define ETH_P_IPV6 0x86DD

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
	u16 state;
}TCPStateValue;

#define SESSION_INFO 1
#define TCP_INFO 2
typedef struct closeStateValue {
	SessionStateValue sessionState;
	TCPStateValue tcpState;
}CloseStateValue;

struct forTupleKey *unused_four_tuple_key_t  __attribute__((unused));
struct bindCheckValue *unused_bind_Check_value_t  __attribute__((unused));

struct processSessionKey *unused_process_session_key_t  __attribute__((unused));
struct sessionStateValue *unused_session_statue_value_t  __attribute__((unused));
struct tcpStateValue *unused_tcp_state_value_t  __attribute__((unused));
struct closeStateValue *unused_close_state_value_t  __attribute__((unused));



// MAP //

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(FourTupleKey));
	__uint(value_size, sizeof(BindCheckValue));
	__uint(max_entries, 1024);
} bindCheckMap SEC(".maps");

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

/*
 * 현재는 미사용, agent에서 알아서 삭제 하도록 처리
 *
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(ProcessSessionKey));
	__uint(value_size, sizeof(CloseStateValue));
	__uint(max_entries, 1024);
} closeStateMap SEC(".maps");
*/
// ETC //


enum {
	BPF_RET_ERROR = -1,
	BPF_RET_OK = 0,
	BPF_RET_UNKNOWN = 1,
};

#endif //__TCP_H__
