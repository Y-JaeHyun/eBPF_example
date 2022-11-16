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

type resourceKey struct {
	ip           string
	resourceType string
	port         int32
}

type resourceInfo struct {
	namespace    string
	resourceName string
}

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

	return diff
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

func setSourceInfo(p *pack.TagCountPack, ip, port, namespace, service, pod, container string) {
	p.PutTag("SourceIP", ip)
	p.PutTag("SourcePort", port)
	p.PutTag("SourceNamespace", namespace)
	p.PutTag("SourceServiceName", service)
	p.PutTag("SourcePodName", pod)
	p.PutTag("SourceContainerName", container)
}

func setDestinationInfo(p *pack.TagCountPack, ip, port, namespace, service, pod, container string) {
	p.PutTag("DestinationIP", ip)
	p.PutTag("DestinationPort", port)
	p.PutTag("DestinationNamespace", namespace)
	p.PutTag("DestinationServiceName", service)
	p.PutTag("DestinationPodName", pod)
	p.PutTag("DestinationContainerName", container)
}

func getResource(ip string, port int32, resourceMap map[resourceKey]resourceInfo) (namespace, service, pod, container string) {
	key := resourceKey{}
	key.ip = ip
	key.resourceType = "Pod"
	key.port = port

	if v, ok := resourceMap[key]; ok {
		namespace = v.namespace
		pod = v.resourceName
		service = "Unknown"

		key.resourceType = "Container"

		if v, ok := resourceMap[key]; ok {
			container = v.resourceName
		} else {
			container = "Unknown"
		}
	} else {
		container = "Unknown"
		key.port = 0

		if v, ok := resourceMap[key]; ok {
			namespace = v.namespace
			pod = v.resourceName
			service = "Unknown"
		} else {
			pod = "Unknown"

			key.resourceType = "Conatainer"

			if v, ok := resourceMap[key]; ok {
				namespace = v.namespace
				service = v.resourceName
			} else {
				namespace = "Unknown"
				service = "Unknown"
			}
		}

	}
	return
}

func setPackTagOut(p *pack.TagCountPack, key *bpfProcessSessionKey, resourceMap map[resourceKey]resourceInfo) error {
	var ip string
	var port string
	var namespace string
	var service string
	var pod string
	var container string

	if key.FourTuple.Ipv == 4 {

		//source info
		ip = int2ip(key.FourTuple.Saddr).String()
		port = fmt.Sprintf("%d", key.FourTuple.Sport)

		namespace, service, pod, container = getResource(ip, int32(key.FourTuple.Sport), resourceMap)

		setSourceInfo(p, ip, port, namespace, service, pod, container)

		//destination info
		ip = int2ip(key.FourTuple.Daddr).String()
		port = fmt.Sprintf("%d", key.FourTuple.Dport)

		namespace, service, pod, container = getResource(ip, int32(key.FourTuple.Dport), resourceMap)

		setDestinationInfo(p, ip, port, namespace, service, pod, container)

		// container는 port 항상 지정되어야함
	} else if key.FourTuple.Ipv == 6 {
		fmt.Println(key)
		// TODO
		return errors.New("TODO")
	}
	p.PutTag("Pid", fmt.Sprintf("%d", key.Pid))
	return nil
}

// ServerType ip/port Revserse
func setPackTagIn(p *pack.TagCountPack, key *bpfProcessSessionKey, resourceMap map[resourceKey]resourceInfo) error {
	if key.FourTuple.Ipv == 4 {

		var ip string
		var port string
		var namespace string
		var service string
		var pod string
		var container string

		//source info
		ip = int2ip(key.FourTuple.Daddr).String()
		port = fmt.Sprintf("%d", key.FourTuple.Dport)

		namespace, service, pod, container = getResource(ip, int32(key.FourTuple.Dport), resourceMap)

		setSourceInfo(p, ip, port, namespace, service, pod, container)

		//destination info
		ip = int2ip(key.FourTuple.Saddr).String()
		port = fmt.Sprintf("%d", key.FourTuple.Sport)

		namespace, service, pod, container = getResource(ip, int32(key.FourTuple.Sport), resourceMap)

		setDestinationInfo(p, ip, port, namespace, service, pod, container)

	} else {
		// TODO
		return errors.New("TODO")
	}
	p.PutTag("Pid", fmt.Sprintf("%d", key.Pid))
	return nil
}

func sendTcpSessionPack(key *bpfProcessSessionKey, sessionState *bpfSessionStateValue, tcpState *bpfTcpStateValue, onewayClient *oneway.OneWayTcpClient, resourceMap map[resourceKey]resourceInfo) error {
	sessionPack := pack.NewTagCountPack()
	sessionPack.Category = "tcpSessionState"
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

	//	tcpPack.Put("RetransCount", tcpState.RetransCount)
	//	tcpPack.Put("LostCount", tcpState.LostCount)
	sessionPack.Put("Latency", tcpState.Latency)
	sessionPack.Put("Jitter", tcpState.Jitter)

	fmt.Println(sessionPack)
	err := onewayClient.Send(sessionPack)
	if err != nil {
		return err
	}

	return nil
}

func getStateData(key bpfProcessSessionKey, sData *stateData, sessionState bpfSessionStateValue, tcpState bpfTcpStateValue) {
	if oldDataMap[key] == nil {
		sData.SessionState = sessionState
		sData.TcpState = tcpState
		oldDataMap[key] = sData
	} else {
		//Session State 변화가 없으면 Tcp State도 의미없음
		if !cmp.Equal(oldDataMap[key].SessionState, sessionState) {

			sData.SessionState = diffSessionState(sessionState, oldDataMap[key].SessionState)
			sData.TcpState = diffTcpState(tcpState, oldDataMap[key].TcpState)

			oldDataMap[key].SessionState = sessionState
			oldDataMap[key].TcpState = tcpState
		}
	}

}
func getIntervalData(objs bpfObjects, onewayClient *oneway.OneWayTcpClient, resourceMap map[resourceKey]resourceInfo) {
	var key bpfProcessSessionKey
	var sessionState bpfSessionStateValue
	var tcpState bpfTcpStateValue
	var closeState bpfCloseStateValue

	iter := objs.SessionStateMap.Iterate()
	for {
		sData := &stateData{}
		ret := iter.Next(&key, &sessionState)
		if !ret {
			break
		}
		objs.TcpStateMap.Lookup(key, &tcpState)

		// Close 이후 동일 키값으로 세션 발생 케이스
		err := objs.CloseStateMap.Lookup(key, &closeState)
		if err != nil && (closeState.SessionState.SendCount > 0 || closeState.SessionState.RecvCount > 0) {
			sData := &stateData{}
			getStateData(key, sData, closeState.SessionState, closeState.TcpState)
			delete(oldDataMap, key)

			if sData.SessionState.SendCount > 0 || sData.SessionState.RecvCount > 0 {
				err := sendTcpSessionPack(&key, &sData.SessionState, &sData.TcpState, onewayClient, resourceMap)
				if err != nil {
					fmt.Println(err)
				}
			}

			objs.CloseStateMap.Delete(key)
		}

		// 현재 세션에 대한 케이스
		getStateData(key, sData, sessionState, tcpState)

		if sData.SessionState.SendCount > 0 || sData.SessionState.RecvCount > 0 {
			err := sendTcpSessionPack(&key, &sData.SessionState, &sData.TcpState, onewayClient, resourceMap)
			if err != nil {
				fmt.Println(err)
			}
		}
	}

	// TODO 별도 루틴으로 뺴야할지 검토 필요
	// Close이후 동일 세션 미발생 케이스
	iter = objs.CloseStateMap.Iterate()
	for {

		sData := &stateData{}
		ret := iter.Next(&key, &closeState)
		if !ret {
			break
		}

		getStateData(key, sData, closeState.SessionState, closeState.TcpState)
		delete(oldDataMap, key)

		if oldDataMap[key] == nil {
			sData.SessionState = closeState.SessionState
			sData.TcpState = closeState.TcpState
		} else {
			if !cmp.Equal(oldDataMap[key].SessionState, sessionState) {
				sData.SessionState = diffSessionState(closeState.SessionState, oldDataMap[key].SessionState)
				sData.TcpState = diffTcpState(closeState.TcpState, oldDataMap[key].TcpState)
			}
			delete(oldDataMap, key)
		}

		if sData.SessionState.SendCount > 0 || sData.SessionState.RecvCount > 0 {
			err := sendTcpSessionPack(&key, &sData.SessionState, &sData.TcpState, onewayClient, resourceMap)
			if err != nil {
				fmt.Println(err)
			}
		}
		objs.CloseStateMap.Delete(key)
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

func getKuberResourceMap() map[resourceKey]resourceInfo {
	resourceMap := make(map[resourceKey]resourceInfo)

	//k8s
	config, err := rest.InClusterConfig()
	if err != nil {
		//fmt.Println(err)
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

	for nsIdx := 0; nsIdx < len(nslist.Items); nsIdx++ {
		nsName := nslist.Items[nsIdx].ObjectMeta.Name
		serviceList, err := cliSet.CoreV1().Services(nsName).List(context.TODO(), v1.ListOptions{})
		if err != nil {
			fmt.Println(err)
			return nil
		}

		for serviceIdx := 0; serviceIdx < len(serviceList.Items); serviceIdx++ {
			key := resourceKey{}
			key.ip = serviceList.Items[serviceIdx].Spec.ClusterIP
			key.resourceType = "Service"
			key.port = 0

			info := resourceInfo{}
			info.namespace = nsName
			info.resourceName = serviceList.Items[serviceIdx].ObjectMeta.Name

			resourceMap[key] = info
		}

		podList, err := cliSet.CoreV1().Pods(nsName).List(context.TODO(), v1.ListOptions{})
		if err != nil {
			fmt.Println(err)
			return nil
		}

		for podIdx := 0; podIdx < len(podList.Items); podIdx++ {
			pKey := resourceKey{}
			pKey.ip = podList.Items[podIdx].Status.PodIP
			pKey.resourceType = "Pod"
			pKey.port = 0

			podInfo := resourceInfo{}
			podInfo.namespace = nsName
			podInfo.resourceName = podList.Items[podIdx].ObjectMeta.Name

			resourceMap[pKey] = podInfo

			containers := podList.Items[podIdx].Spec.Containers

			for containerIdx := 0; containerIdx < len(containers); containerIdx++ {
				cKey := resourceKey{}
				cKey.ip = pKey.ip
				cKey.resourceType = "Container"

				cInfo := resourceInfo{}
				cInfo.namespace = nsName
				cInfo.resourceName = containers[containerIdx].Name
				ports := containers[containerIdx].Ports
				if len(ports) == 0 {
					continue
				}

				// Pod, Container 동시 갱신
				// 동일 IP 포트 발생 가능 CASE 확인되어 Port 까지 확인하는 케이스 추가
				for portIdx := 0; portIdx < len(ports); portIdx++ {
					cKey.port = ports[portIdx].ContainerPort
					pKey.port = cKey.port

					resourceMap[pKey] = podInfo
					resourceMap[cKey] = cInfo
				}
			}

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
	servers = append(servers, "15.165.146.117:6600")
	accessKey := "x2jgg66m4jlck-z6l4o2nb3cckq0-x5jfk4ktaqmfth"

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
		"tcp_connect":      objs.KprobeTcpConnect,
		"tcp_set_state":    objs.KprobeTcpSetState,
		"tcp_sendmsg":      objs.KprobeTcpSendmsg,
		"tcp_cleanup_rbuf": objs.KprobeTcpCleanupRbpf,
		"tcp_close":        objs.KprobeTcpClose,
		//"inet_csk_listen_stop": objs.KprobeInetCskListenStop,
		"tcp_finish_connect": objs.KprobeTcpFinishConnect,
		/*
			"inet_bind":            objs.KprobeInetBind,
			"ip_make_skb":          objs.KprobeIpMakeSkb,
			"udp_recvmsg":          objs.KprobeUdpRecvmsg,
			"skb_consume_udp":      objs.KprobeSkbConsumeUdp,
		*/
	}

	var kretprobeMap = map[string]*ebpf.Program{
		"tcp_connect":      objs.KretprobeTcpConnect,
		"inet_csk_accept":  objs.KretprobeInetCskAccept,
		"tcp_sendmsg":      objs.KretprobeTcpSendmsg,
		"tcp_cleanup_rbuf": objs.KretprobeTcpCleanupRbpf,
		//"inet_bind":        objs.KretprobeInetBind,
		/*
			"ip_make_skb":     objs.KretprobeIpMakeSkb,
			"udp_recvmsg":     objs.KretprobeUdpRecvmsg,
			"skb_consume_udp": objs.KretprobeSkbConsumeUdp,
		*/
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
