package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/go-cmp/cmp"
	"github.com/whatap/golib/io"
	"github.com/whatap/golib/lang/pack"
	"github.com/whatap/golib/net/oneway"
	"github.com/whatap/golib/util/hexa32"
)

type stateData struct {
	SessionState bpfSessionStateValue
	TcpState     bpfTcpStateValue
}

const (
	intervalTime = 5
)

var (
	oldDataMap = make(map[bpfProcessSessionKey]*stateData)
)

var etherMap = map[uint16]string{
	32768: "IPv4", // Ether Type: 0x8000
	34525: "IPv6", // Ether Type: 0x86DD
}

var directionMap = map[uint8]string{
	1: "IN",
	2: "OUT",
}
var protocolMap = map[uint8]string{
	6:  "TCP",
	17: "UDP",
}

var pcode int64

func checkEnvPath(env string) (string, error) {
	filePath, _ := os.LookupEnv(env)
	if filePath != "" {
		_, err := os.Stat(filePath)
		if err != nil {
			return "", fmt.Errorf("could not open %s %s", env, filePath)
		}
		return filePath, nil
	}
	return "", nil
}

func diffSessionState(totalState, oldState bpfSessionStateValue) bpfSessionStateValue {
	diff := bpfSessionStateValue{}
	diff.Ether = totalState.Ether
	diff.Direction = totalState.Direction
	diff.Protocol = totalState.Protocol
	diff.SendCount = totalState.SendCount - oldState.SendCount
	diff.RecvCount = totalState.RecvCount - oldState.RecvCount
	diff.SendByte = totalState.SendByte - oldState.SendByte
	diff.RecvByte = totalState.RecvByte - oldState.RecvByte

	return diff
}

func diffTcpState(totalState, oldState bpfTcpStateValue) bpfTcpStateValue {
	diff := bpfTcpStateValue{}
	diff.RetransCount = totalState.RetransCount - oldState.RetransCount
	diff.LostCount = totalState.LostCount - oldState.LostCount
	diff.Latency = totalState.Latency
	diff.Jitter = totalState.Jitter
	diff.State = totalState.State

	return diff
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

func setPackTag(p *pack.TagCountPack, key *bpfProcessSessionKey) {
	p.PutTag("SourcePort", fmt.Sprintf("%d", key.FourTuple.Sport))
	p.PutTag("DestinationPort", fmt.Sprintf("%d", key.FourTuple.Dport))
	if key.FourTuple.Ipv == 4 {
		sourceIP := int2ip(key.FourTuple.Sip.Saddr)
		p.PutTag("SourceIp", sourceIP.String())
		destinationIP := int2ip(key.FourTuple.Dip.Daddr)
		p.PutTag("DestinationIp", destinationIP.String())
	} else {
		// TODO
	}
	p.PutTag("Pid", fmt.Sprintf("%d", key.Pid))
}

func sendSessionPack(key *bpfProcessSessionKey, sessionState *bpfSessionStateValue, onewayClient *oneway.OneWayTcpClient) error {
	sessionPack := pack.NewTagCountPack()
	sessionPack.Category = "sessionState"
	sessionPack.Time = time.Now().UnixNano() / int64(time.Millisecond)
	sessionPack.SetPCODE(pcode)

	setPackTag(sessionPack, key)
	sessionPack.Put("Ethernet", etherMap[sessionState.Ether])
	sessionPack.Put("Driection", directionMap[sessionState.Direction])
	sessionPack.Put("Protocol", protocolMap[sessionState.Protocol])
	sessionPack.Put("SendCount", sessionState.SendCount)
	sessionPack.Put("RecvCount", sessionState.RecvCount)
	sessionPack.Put("SendByte", sessionState.SendByte)
	sessionPack.Put("RecvByte", sessionState.RecvByte)

	fmt.Println(sessionPack)
	err := onewayClient.Send(sessionPack)
	if err != nil {
		return err
	}

	return nil
}

func sendTcpPack(key *bpfProcessSessionKey, tcpState *bpfTcpStateValue, onewayClient *oneway.OneWayTcpClient) error {
	tcpPack := pack.NewTagCountPack()
	tcpPack.Category = "tcpState"
	tcpPack.Time = time.Now().UnixNano() / int64(time.Millisecond)
	tcpPack.SetPCODE(pcode)

	setPackTag(tcpPack, key)
	//	tcpPack.Put("RetransCount", tcpState.RetransCount)
	//	tcpPack.Put("LostCount", tcpState.LostCount)
	tcpPack.Put("Latency", tcpState.Latency)
	tcpPack.Put("Jitter", tcpState.Jitter)
	//tcpPack.Put("")

	fmt.Println(tcpPack)
	err := onewayClient.Send(tcpPack)
	if err != nil {
		return err
	}
	return nil
}

func getIntervalData(objs bpfObjects, onewayClient *oneway.OneWayTcpClient) {
	var key bpfProcessSessionKey
	var sessionState bpfSessionStateValue
	var tcpState bpfTcpStateValue
	//var closeState bpfCloseStateValue

	iter := objs.SessionStateMap.Iterate()
	for {
		sData := &stateData{}
		ret := iter.Next(&key, &sessionState)
		if !ret {
			break
		}
		objs.TcpStateMap.Lookup(key, &tcpState)

		if oldDataMap[key] == nil {
			sData.SessionState = sessionState
			sData.TcpState = tcpState
			oldDataMap[key] = sData
		} else {
			if cmp.Equal(oldDataMap[key].SessionState, sessionState) && cmp.Equal(oldDataMap[key].TcpState, tcpState) {
				continue
			}
			sData.SessionState = diffSessionState(sessionState, oldDataMap[key].SessionState)
			sData.TcpState = diffTcpState(tcpState, oldDataMap[key].TcpState)

			oldDataMap[key].SessionState = sessionState
			oldDataMap[key].TcpState = tcpState
		}

		sendSessionPack(&key, &sData.SessionState, onewayClient)
		sendTcpPack(&key, &sData.TcpState, onewayClient)

	}

}

func checkTime(interval int, objs bpfObjects, onewayClient *oneway.OneWayTcpClient) {
	ticker := time.NewTicker(time.Second * 1)
	defer ticker.Stop()
	defer func() {
		if r := recover(); r != nil {
			log.Println("CheckTime Panic: ", r)
		}
	}()
	for t := range ticker.C {
		second := t.Second()
		if second%interval == 0 {
			getIntervalData(objs, onewayClient)
		}
	}
}

// TODO gointernal license로 변경
func Parse(lic string) (int64, []byte) {
	tokens := strings.Split(lic, "-")
	out := io.NewDataOutputX()
	for i := 0; i < len(tokens); i++ {
		out.WriteLong(hexa32.ToLong32(tokens[i]))
	}
	in := io.NewDataInputX(out.ToByteArray())
	pcode := in.ReadDecimal()
	security_key := in.ReadBlob()
	return pcode, security_key
}

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags -O2 -type processSessionKey -type sessionStateValue -type tcpStateValue -type closeStateValue bpf tcp.c -- -I../headers

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	servers := make([]string, 0)
	servers = append(servers, "")
	accessKey := ""

	pcode, _ = Parse(accessKey)

	onewayClient := oneway.GetOneWayTcpClient(oneway.WithServers(servers), oneway.WithLicense(accessKey), oneway.WithUseQueue())
	defer onewayClient.Close()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Println(err)
	}

	// Load BTF
	// TODO BTF File 배포 방법 검토 필요
	defaultPath := "/sys/kernel/btf/vmlinux"
	fd, err := os.Open(defaultPath)
	if err != nil {
		path, err := checkEnvPath("EXTERN_BTF_FILE")
		if err != nil {
			fmt.Println(err)
			return
		}
		fd, err = os.Open(path)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	spec, err := btf.LoadSpecFromReader(fd)
	if err != nil {
		fmt.Println(err)
		return
	}

	cs := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: spec,
		},
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, cs); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	var kprobeMap = map[string]*ebpf.Program{
		"tcp_connect":          objs.KprobeTcpConnect,
		"tcp_set_state":        objs.KprobeTcpSetState,
		"tcp_sendmsg":          objs.KprobeTcpSendmsg,
		"tcp_cleanup_rbuf":     objs.KprobeTcpCleanupRbpf,
		"tcp_close":            objs.KprobeTcpClose,
		"inet_csk_listen_stop": objs.KprobeInetCskListenStop,
		"tcp_finish_connect":   objs.KprobeTcpFinishConnect,
	}

	var kretprobeMap = map[string]*ebpf.Program{
		"tcp_connect":      objs.KretprobeTcpConnect,
		"inet_csk_accept":  objs.KretprobeInetCskAccept,
		"tcp_sendmsg":      objs.KretprobeTcpSendmsg,
		"tcp_cleanup_rbuf": objs.KretprobeTcpCleanupRbpf,
	}

	linkSlice := make([]link.Link, 0)
	for k, v := range kprobeMap {
		link, err := link.Kprobe(k, v, nil)
		if err != nil {
			fmt.Println(err)
		} else {
			linkSlice = append(linkSlice, link)
		}
	}
	for k, v := range kretprobeMap {
		link, err := link.Kretprobe(k, v, nil)
		if err != nil {
			fmt.Println(err)
		} else {
			linkSlice = append(linkSlice, link)
		}
	}
	defer func() {
		for _, v := range linkSlice {
			v.Close()
		}
	}()

	go checkTime(intervalTime, objs, onewayClient)

	<-stopper
}
