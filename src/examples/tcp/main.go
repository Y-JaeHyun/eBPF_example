package main

import (
	"context"
	"encoding/binary"
	"errors"
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
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type stateData struct {
	SessionState bpfSessionStateValue
	TcpState     bpfTcpStateValue
}

const (
	intervalTime = 5
)

const (
	TCP_ESTABLISHED = 1
	TCP_SYN_SENT    = 2
	TCP_SYN_RECV    = 3
	TCP_FIN_WAIT1   = 4
	TCP_FIN_WAIT2   = 5
	TCP_TIME_WAIT   = 6
	TCP_CLOSE       = 7
	TCP_LISTEN      = 10
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
	if totalState.SendCount >= oldState.SendCount {
		diff.SendCount = totalState.SendCount - oldState.SendCount
	} else {
		diff.SendCount = ^uint32(0) - oldState.SendCount + totalState.SendCount
	}

	if totalState.RecvCount >= oldState.RecvCount {
		diff.RecvCount = totalState.RecvCount - oldState.RecvCount
	} else {
		diff.RecvCount = ^uint32(0) - oldState.RecvCount + totalState.RecvCount
	}

	if totalState.SendByte >= oldState.SendByte {
		diff.SendByte = totalState.SendByte - oldState.SendByte
	} else {
		diff.SendByte = ^uint64(0) - oldState.SendByte + totalState.SendByte
	}

	if totalState.RecvByte >= oldState.RecvByte {
		diff.RecvByte = totalState.RecvByte - oldState.RecvByte
	} else {
		diff.SendByte = ^uint64(0) - oldState.SendByte + totalState.SendByte
	}

	return diff
}

func diffTcpState(totalState, oldState bpfTcpStateValue) bpfTcpStateValue {
	diff := bpfTcpStateValue{}
	if totalState.RetransCount >= oldState.RetransCount {
		diff.RetransCount = totalState.RetransCount - oldState.RetransCount
	} else {
		diff.RetransCount = ^uint32(0) - oldState.RetransCount + totalState.RetransCount
	}

	if totalState.LostCount >= oldState.LostCount {
		diff.LostCount = totalState.LostCount - oldState.LostCount
	} else {
		diff.LostCount = ^uint32(0) - oldState.LostCount + totalState.LostCount
	}
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

func setPackTagOut(p *pack.TagCountPack, key *bpfProcessSessionKey, resourceMap map[string]resourceInfo) error {
	p.PutTag("SourcePort", fmt.Sprintf("%d", key.FourTuple.Sport))
	p.PutTag("DestinationPort", fmt.Sprintf("%d", key.FourTuple.Dport))
	if key.FourTuple.Ipv == 4 {
		sourceIP := int2ip(key.FourTuple.Sip.Saddr).String()
		if resourceInfo, ok := resourceMap[sourceIP]; ok {
			fmt.Println(resourceInfo.resourceType, " : ", resourceInfo.resourceName, "!!!!!!!")
			p.PutTag("SourceType", resourceInfo.resourceType)
			p.PutTag("SourceName", resourceInfo.resourceName)
		} else {
			p.PutTag("SourceType", "Unknown")
			p.PutTag("SourceName", "Unknown")
		}
		p.PutTag("SourceIp", sourceIP)
		destinationIP := int2ip(key.FourTuple.Dip.Daddr).String()
		if resourceInfo, ok := resourceMap[destinationIP]; ok {
			fmt.Println(resourceInfo.resourceType, " : ", resourceInfo.resourceName, "!!!!!!!")
			p.PutTag("DestinationType", resourceInfo.resourceType)
			p.PutTag("DestinationName", resourceInfo.resourceName)
		} else {
			p.PutTag("DestinationType", "Unknown")
			p.PutTag("DestinationName", "Unknown")
		}
		p.PutTag("DestinationIp", destinationIP)
	} else {
		// TODO
		return errors.New("TODO")
	}
	p.PutTag("Pid", fmt.Sprintf("%d", key.Pid))
	return nil
}

// ServerType
func setPackTagIn(p *pack.TagCountPack, key *bpfProcessSessionKey, resourceMap map[string]resourceInfo) error {
	p.PutTag("SourcePort", fmt.Sprintf("%d", key.FourTuple.Dport))
	p.PutTag("DestinationPort", fmt.Sprintf("%d", key.FourTuple.Sport))
	if key.FourTuple.Ipv == 4 {
		sourceIP := int2ip(key.FourTuple.Sip.Saddr).String()
		if resourceInfo, ok := resourceMap[sourceIP]; ok {
			fmt.Println(resourceInfo.resourceType, " : ", resourceInfo.resourceName, "!!!!!!!")
			p.PutTag("DestinationType", resourceInfo.resourceType)
			p.PutTag("DestinationName", resourceInfo.resourceName)
		} else {
			p.PutTag("DestinationType", "Unknown")
			p.PutTag("DestinationName", "Unknown")
		}
		p.PutTag("DestinationIp", sourceIP)
		destinationIP := int2ip(key.FourTuple.Dip.Daddr).String()
		if resourceInfo, ok := resourceMap[destinationIP]; ok {
			fmt.Println(resourceInfo.resourceType, " : ", resourceInfo.resourceName, "!!!!!!!")
			p.PutTag("SourceType", resourceInfo.resourceType)
			p.PutTag("SourceName", resourceInfo.resourceName)
		} else {
			p.PutTag("SourceType", "Unknown")
			p.PutTag("SourceName", "Unknown")
		}
		p.PutTag("SourceIp", destinationIP)
	} else {
		// TODO
		return errors.New("TODO")
	}
	p.PutTag("Pid", fmt.Sprintf("%d", key.Pid))
	return nil
}
func sendSessionPack(key *bpfProcessSessionKey, sessionState *bpfSessionStateValue, onewayClient *oneway.OneWayTcpClient, resourceMap map[string]resourceInfo) error {
	sessionPack := pack.NewTagCountPack()
	sessionPack.Category = "sessionState"
	sessionPack.Time = time.Now().UnixNano() / int64(time.Millisecond)
	sessionPack.SetPCODE(pcode)

	if sessionState.Direction == 1 {
		err := setPackTagIn(sessionPack, key, resourceMap)
		if err != nil {
			return err
		}
	} else {
		err := setPackTagOut(sessionPack, key, resourceMap)
		if err != nil {
			return err
		}
	}
	sessionPack.Put("Ethernet", etherMap[sessionState.Ether])
	sessionPack.Put("Driection", directionMap[sessionState.Direction])
	sessionPack.Put("Protocol", protocolMap[sessionState.Protocol])

	if sessionState.Direction == 1 {
		sessionPack.Put("SendCount", sessionState.RecvCount)
		sessionPack.Put("RecvCount", sessionState.SendCount)
		sessionPack.Put("SendByte", sessionState.RecvByte)
		sessionPack.Put("RecvByte", sessionState.SendByte)

	} else {
		sessionPack.Put("SendCount", sessionState.SendCount)
		sessionPack.Put("RecvCount", sessionState.RecvCount)
		sessionPack.Put("SendByte", sessionState.SendByte)
		sessionPack.Put("RecvByte", sessionState.RecvByte)
	}

	fmt.Println(sessionPack)
	err := onewayClient.Send(sessionPack)
	if err != nil {
		return err
	}

	return nil
}

func sendTcpPack(key *bpfProcessSessionKey, tcpState *bpfTcpStateValue, onewayClient *oneway.OneWayTcpClient, resourceMap map[string]resourceInfo, directions uint8) error {
	tcpPack := pack.NewTagCountPack()
	tcpPack.Category = "tcpState"
	tcpPack.Time = time.Now().UnixNano() / int64(time.Millisecond)
	tcpPack.SetPCODE(pcode)

	if directions == 1 {
		err := setPackTagIn(tcpPack, key, resourceMap)
		if err != nil {
			return err
		}
	} else {
		err := setPackTagOut(tcpPack, key, resourceMap)
		if err != nil {
			return err
		}
	}

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

// 4Tuple 기준으로 Close 된 모든 항목을 삭제해야함
// TODO 매번 모든 Key값을 검토해야하기 떄문에 성능상 문제가 있을수 있음, 개선 필요
// TODO2 일반적인 상황이 아니라 close 등의 이벤트를 받지 못하면 Delete 가 영원히 지속됨
func deleteDataWithFourTuple(keys []*bpfProcessSessionKey, objs bpfObjects) {
	var mKey bpfProcessSessionKey
	var sessionState bpfSessionStateValue

	for _, dKey := range keys {
		iter := objs.SessionStateMap.Iterate()
		for {
			ret := iter.Next(&mKey, &sessionState)
			if !ret {
				break
			}

			if cmp.Equal(mKey.FourTuple, dKey.FourTuple) {
				objs.SessionStateMap.Delete(mKey)
				objs.TcpStateMap.Delete(mKey)
			}
		}
	}
}

func getIntervalData(objs bpfObjects, onewayClient *oneway.OneWayTcpClient, resourceMap map[string]resourceInfo) {
	var key bpfProcessSessionKey
	var sessionState bpfSessionStateValue
	var tcpState bpfTcpStateValue
	//var closeState bpfCloseStateValue

	deleteTuple := make([]*bpfProcessSessionKey, 0)
	iter := objs.SessionStateMap.Iterate()
	for {
		sData := &stateData{}
		ret := iter.Next(&key, &sessionState)
		if !ret {
			break
		}
		objs.TcpStateMap.Lookup(key, &tcpState)

		if tcpState.State&(1<<TCP_CLOSE) > 0 {
			deleteTuple = append(deleteTuple, &key)
			//objs.SessionStateMap.Delete(key)
			//objs.TcpStateMap.Delete(key)
		}

		if oldDataMap[key] == nil {
			sData.SessionState = sessionState
			sData.TcpState = tcpState
			oldDataMap[key] = sData
		} else {
			//Session State 변화가 없으면 Tcp State도 의미없음
			if cmp.Equal(oldDataMap[key].SessionState, sessionState) {
				continue
			}

			sData.SessionState = diffSessionState(sessionState, oldDataMap[key].SessionState)
			sData.TcpState = diffTcpState(tcpState, oldDataMap[key].TcpState)

			oldDataMap[key].SessionState = sessionState
			oldDataMap[key].TcpState = tcpState
		}

		if sData.SessionState.SendCount > 0 || sData.SessionState.RecvCount > 0 {

			err := sendSessionPack(&key, &sData.SessionState, onewayClient, resourceMap)
			if err != nil {
				fmt.Println(err)
			}
			err = sendTcpPack(&key, &sData.TcpState, onewayClient, resourceMap, sData.SessionState.Direction)
			if err != nil {
				fmt.Println(err)
			}
		}
	}

	deleteDataWithFourTuple(deleteTuple, objs)
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
			resourceMap := getKuberResourceMap()
			getIntervalData(objs, onewayClient, resourceMap)
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

type resourceInfo struct {
	resourceType string
	resourceName string
}

func getKuberResourceMap() map[string]resourceInfo {
	var resourceMap map[string]resourceInfo
	resourceMap = make(map[string]resourceInfo)

	//k8s
	config, err := rest.InClusterConfig()
	if err != nil {
		fmt.Println(err)
		return nil
	}

	cliSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	nslist, err := cliSet.CoreV1().Namespaces().List(context.TODO(), v1.ListOptions{})
	if err != nil {
		fmt.Println(err)
		return nil
	}

	for i := 0; i < len(nslist.Items); i++ {
		fmt.Println("===========================================")
		fmt.Println("name space : ", nslist.Items[i].ObjectMeta.Name)
		podlist, err := cliSet.CoreV1().Pods(nslist.Items[i].ObjectMeta.Name).List(context.TODO(), v1.ListOptions{})
		if err != nil {
			fmt.Println(err)
			return nil
		}

		for i := 0; i < len(podlist.Items); i++ {
			fmt.Println("-----------------------------")
			fmt.Printf("Pod Name[%d] : %s\n", i, podlist.Items[i].ObjectMeta.Name)
			fmt.Printf("Pod IP[%d] : %s\n", i, podlist.Items[i].Status.PodIP)

			resouce := resourceInfo{"POD", podlist.Items[i].ObjectMeta.Name}

			resourceMap[podlist.Items[i].Status.PodIP] = resouce
			//.resourceType = "POD"
			//resourceMap[podlist.Items[i].Status.PodIP].resourceName = podlist.Items[i].ObjectMeta.Name
		}
	}
	return resourceMap
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

	//	resourceMap := getKuberResourceMap()

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
