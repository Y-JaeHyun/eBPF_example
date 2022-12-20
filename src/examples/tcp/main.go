package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/drael/GOnetstat"
	"github.com/whatap/golib/config/conffile"
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
	0: "UNKNOWN",
	1: "IN",
	2: "OUT",
}

var protocolMap = map[uint8]string{
	6:  "TCP",
	17: "UDP",
}

// ConfigKey enum과 매칭되어야함
var configKeyMap = map[string]int32{
	"BPF_LOGTYPE":  1,
	"BPF_LOGLEVEL": 2,
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

func setPackTag(p *pack.TagCountPack, key *bpfProcessSessionKey, resourceMap map[resourceKey]resourceInfo) error {
	var sip string
	var dip string
	var port string
	var namespace string
	var service string
	var pod string
	var container string

	fmt.Println(key)
	if key.FourTuple.Ipv == 32768 {

		//source info
		sip = int2ip(key.FourTuple.Saddr).String()
		//destination info
		dip = int2ip(key.FourTuple.Daddr).String()
		// container는 port 항상 지정되어야함
	} else if key.FourTuple.Ipv == 34525 {
		sip = net.IP(key.FourTuple.Saddrv6.In6U.U6Addr8[:]).String()
		// TODO
		dip = net.IP(key.FourTuple.Daddrv6.In6U.U6Addr8[:]).String()

	}
	port = fmt.Sprintf("%d", key.FourTuple.Sport)
	namespace, service, pod, container = getResource(sip, int32(key.FourTuple.Sport), resourceMap)
	setSourceInfo(p, sip, port, namespace, service, pod, container)

	port = fmt.Sprintf("%d", key.FourTuple.Dport)
	namespace, service, pod, container = getResource(dip, int32(key.FourTuple.Dport), resourceMap)
	setDestinationInfo(p, dip, port, namespace, service, pod, container)

	p.PutTag("Pid", fmt.Sprintf("%d", key.Pid))
	return nil
}

/*
// ServerType ip/port Revserse
func setPackTagIn(p *pack.TagCountPack, key *bpfProcessSessionKey, resourceMap map[resourceKey]resourceInfo) error {
	if key.FourTuple.Ipv == 32768 {

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
*/

func sendUdpSessionPack(key *bpfProcessSessionKey, sessionState *bpfSessionStateValue, onewayClient *oneway.OneWayTcpClient, resourceMap map[resourceKey]resourceInfo) error {
	sessionPack := pack.NewTagCountPack()
	sessionPack.Category = "udpSessionState"
	sessionPack.Time = time.Now().UnixNano() / int64(time.Millisecond)
	sessionPack.SetPCODE(pcode)

	err := setPackTag(sessionPack, key, resourceMap)
	if err != nil {
		return err
	}

	sessionPack.Put("Ethernet", etherMap[sessionState.Ether])
	sessionPack.Put("Driection", directionMap[sessionState.Direction])
	sessionPack.Put("Protocol", protocolMap[sessionState.Protocol])
	sessionPack.Put("SendCount", sessionState.SendCount)
	sessionPack.Put("RecvCount", sessionState.RecvCount)
	sessionPack.Put("SendByte", sessionState.SendByte)
	sessionPack.Put("RecvByte", sessionState.RecvByte)

	fmt.Println(sessionPack)
	err = onewayClient.Send(sessionPack)
	if err != nil {
		return err
	}

	return nil
}

func sendTcpSessionPack(key *bpfProcessSessionKey, sessionState *bpfSessionStateValue, tcpState *bpfTcpStateValue, onewayClient *oneway.OneWayTcpClient, resourceMap map[resourceKey]resourceInfo) error {
	sessionPack := pack.NewTagCountPack()
	sessionPack.Category = "tcpSessionState"
	sessionPack.Time = time.Now().UnixNano() / int64(time.Millisecond)
	sessionPack.SetPCODE(pcode)

	err := setPackTag(sessionPack, key, resourceMap)
	if err != nil {
		return err
	}

	sessionPack.Put("Ethernet", etherMap[sessionState.Ether])
	sessionPack.Put("Driection", directionMap[sessionState.Direction])
	sessionPack.Put("Protocol", protocolMap[sessionState.Protocol])
	sessionPack.Put("SendCount", sessionState.SendCount)
	sessionPack.Put("RecvCount", sessionState.RecvCount)
	sessionPack.Put("SendByte", sessionState.SendByte)
	sessionPack.Put("RecvByte", sessionState.RecvByte)
	sessionPack.Put("Latency", tcpState.Latency)
	sessionPack.Put("Jitter", tcpState.Jitter)

	fmt.Println(sessionPack)
	err = onewayClient.Send(sessionPack)
	if err != nil {
		return err
	}

	return nil
}

func getSessionState(key bpfProcessSessionKey, sData *stateData, sessionState bpfSessionStateValue) uint8 {
	if oldDataMap[key] == nil {
		sData.SessionState = sessionState
	} else {
		sData.SessionState = diffSessionState(sessionState, oldDataMap[key].SessionState)
	}
	oldDataMap[key].SessionState = sessionState

	return sessionState.Protocol
}

func getTcpState(key bpfProcessSessionKey, sData *stateData, tcpState bpfTcpStateValue) {
	if oldDataMap[key] == nil {
		sData.TcpState = tcpState
	} else {
		sData.TcpState = diffTcpState(tcpState, oldDataMap[key].TcpState)
	}
	oldDataMap[key].TcpState = tcpState
}

func checkSessionEvent(key bpfProcessSessionKey, sessionState bpfSessionStateValue, tcpState bpfTcpStateValue, onewayClient *oneway.OneWayTcpClient, resourceMap map[resourceKey]resourceInfo) {
	sData := &stateData{}

	if oldDataMap[key] == nil {
		oldDataMap[key] = sData
	}

	protocol := getSessionState(key, sData, sessionState)
	fmt.Println("check event")
	fmt.Println(protocol)
	fmt.Println(sData.SessionState)
	if sData.SessionState.SendCount > 0 || sData.SessionState.RecvCount > 0 {
		if protocol == 6 { // TCP
			getTcpState(key, sData, tcpState)

			err := sendTcpSessionPack(&key, &sData.SessionState, &sData.TcpState, onewayClient, resourceMap)
			if err != nil {
				fmt.Println(err)
			}
		} else if protocol == 17 { // UDP
			//sendUDPSessionPack

			err := sendUdpSessionPack(&key, &sData.SessionState, onewayClient, resourceMap)
			if err != nil {
				fmt.Println(err)
			}
		} else {
		}
	}

}

//TODO Refectoring..

func intervalProcess(objs bpfObjects, onewayClient *oneway.OneWayTcpClient, resourceMap map[resourceKey]resourceInfo) {
	var key bpfProcessSessionKey
	var sessionState bpfSessionStateValue
	var tcpState bpfTcpStateValue
	var closeState bpfCloseStateValue

	iter := objs.SessionStateMap.Iterate()
	for {
		ret := iter.Next(&key, &sessionState)
		if !ret {
			break
		}

		// Close 이후 동일 키값으로 세션 발생 케이스
		err := objs.CloseStateMap.Lookup(key, &closeState)
		if err != nil && (closeState.SessionState.SendCount > 0 || closeState.SessionState.RecvCount > 0) {
			fmt.Println("Close 1")
			checkSessionEvent(key, closeState.SessionState, closeState.TcpState, onewayClient, resourceMap)
			delete(oldDataMap, key)
			objs.CloseStateMap.Delete(key)
		}

		// 현재 세션에 대한 케이스
		fmt.Println("Now")
		objs.TcpStateMap.Lookup(key, &tcpState)
		checkSessionEvent(key, sessionState, tcpState, onewayClient, resourceMap)
	}

	// TODO 별도 루틴으로 뺴야할지 검토 필요
	// Close이후 동일 세션 미발생 케이스
	iter = objs.CloseStateMap.Iterate()
	for {

		ret := iter.Next(&key, &closeState)
		if !ret {
			break
		}

		fmt.Println("Close 2")
		checkSessionEvent(key, closeState.SessionState, closeState.TcpState, onewayClient, resourceMap)

		delete(oldDataMap, key)
		objs.CloseStateMap.Delete(key)
	}

}

func makeString(arr []int8, size int) string {
	b := make([]byte, size)

	for i, v := range arr {
		b[i] = byte(v)
	}

	return string(b)
}

func makeConfigIntValue(num int32) bpfConfigValue {
	var configVal bpfConfigValue
	str := strconv.Itoa(int(num))

	strLen := len(str)
	bufLen := len(configVal.Str)

	for i := 0; i < strLen && i < bufLen; i++ {
		configVal.Str[i] = int8(str[i])
	}

	return configVal
}

func printLog(log bpfLogMessage) string {

	/*
		b := make([]byte, len(log.Func))
		for i, v := range logFunc {
			b[i] = byte(v)
		}
	*/
	funcName := makeString(log.Func[:], len(log.Func))
	message := makeString(log.Message[:], len(log.Message))
	arg := makeString(log.Arg[:], len(log.Arg))

	var logMessage string
	if log.ArgLen == 0 {
		logMessage = fmt.Sprintf("[%s][%d][%d]%s\n", funcName, log.Line, log.Pid, message)
	} else {
		logMessage = fmt.Sprintf("[%s][%d][%d]%s - %s\n", funcName, log.Line, log.Pid, message, arg)
	}

	return logMessage
}

func logCheckTime(interval int, objs bpfObjects) {
	ticker := time.NewTicker(time.Second * 1)
	defer ticker.Stop()
	defer func() {
		if r := recover(); r != nil {
			log.Println("CheckTime Panic: ", r)
		}
	}()
	for t := range ticker.C {
		second := t.Second()
		if second%interval == 2 {
			var log bpfLogMessage
			for {
				if err := objs.LogMap.LookupAndDelete(nil, &log); err != nil {
					continue
				}

				fmt.Println(printLog(log))
			}
		}
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
			intervalProcess(objs, onewayClient, resourceMap)
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
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags -O2 -type processSessionKey -type sessionStateValue -type tcpStateValue -type closeStateValue -type logMessage -type configValue -type ConfigKey bpf tcp.c -- -I../headers

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	//Read Config
	servers := make([]string, 0)
	conf := conffile.GetConfig()
	accessKey := conf.GetValue("accesskey")
	serverList := conf.GetValue("whatap.server.host")
	serverSlice := strings.Split(serverList, "/")
	port := conf.GetInt("net_udp_port", 6600)

	for _, str := range serverSlice {
		servers = append(servers, fmt.Sprintf("%s:%d", str, port))
	}

	bpfLogType := conf.GetInt("bpf_logtype", 0)
	bpfLogLevel := conf.GetInt("bpf_loglevel", 0)

	pcode, _ = Parse(accessKey)

	// TODO oneway -> secure
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

	// Init Map
	// Option Set, Listen Port Set
	// UDP 는 stateless 기반으로 소켓 정보를 통해 server bind port인지 client port인지 구분이 불가함
	// 인지되지 않은 방향은 Unknown으로 처리
	objs.ConfigMap.Put(configKeyMap["BPF_LOGTYPE"], makeConfigIntValue(bpfLogType))
	var val bpfConfigValue
	objs.ConfigMap.Lookup(configKeyMap["BPF_LOGTYPE"], &val)
	fmt.Println(val)
	objs.ConfigMap.Put(configKeyMap["BPF_LOGLEVEL"], makeConfigIntValue(bpfLogLevel))

	tcpStats := GOnetstat.Tcp()
	for _, tcp := range tcpStats {
		if tcp.State == "LISTEN" {
			typeValue := uint16(syscall.SOCK_STREAM)
			portValue := uint16(tcp.Port)
			fmt.Println(syscall.SOCK_STREAM)
			err := objs.BindCheckMap.Put(&portValue, &typeValue)
			fmt.Println(err)
		}
	}
	tcp6Stats := GOnetstat.Tcp6()
	for _, tcp := range tcp6Stats {
		if tcp.State == "LISTEN" {
			typeValue := uint16(syscall.SOCK_STREAM)
			portValue := uint16(tcp.Port)
			fmt.Println(syscall.SOCK_STREAM)
			err := objs.BindCheckMap.Put(&portValue, &typeValue)
			fmt.Println(err)
		}
	}

	var kprobeMap = map[string]*ebpf.Program{
		"tcp_connect":   objs.KprobeTcpConnect,
		"tcp_set_state": objs.KprobeTcpSetState,
		"tcp_sendmsg":   objs.KprobeTcpSendmsg,
		"tcp_recvmsg":   objs.KprobeTcpRecvmsg,
		//"tcp_cleanup_rbuf":     objs.KprobeTcpCleanupRbpf,
		"tcp_close":            objs.KprobeTcpClose,
		"inet_csk_listen_stop": objs.KprobeInetCskListenStop,
		"tcp_finish_connect":   objs.KprobeTcpFinishConnect,
		"inet_bind":            objs.KprobeInetBind,
		"inet_release":         objs.KprobeInetRelease,
		"inet6_bind":           objs.KprobeInet6Bind,
		"inet6_release":        objs.KprobeInet6Release,
		"ip_make_skb":          objs.KprobeIpMakeSkb,
		"ip6_make_skb":         objs.KprobeIp6MakeSkb,
		"udp_recvmsg":          objs.KprobeUdpRecvmsg,
		"udpv6_recvmsg":        objs.KprobeUdpv6Recvmsg,
		"skb_consume_udp":      objs.KprobeSkbConsumeUdp,
		"udp_sendmsg":          objs.KprobeUdpSendmsg,
		"udpv6_sendmsg":        objs.KprobeUdpv6Sendmsg,
		"udp_destroy_sock":     objs.KprobeUdpDestroySock,
		"udpv6_destroy_sock":   objs.KprobeUdpDestroySock,
	}

	var kretprobeMap = map[string]*ebpf.Program{
		"tcp_connect":     objs.KretprobeTcpConnect,
		"inet_csk_accept": objs.KretprobeInetCskAccept,
		"tcp_sendmsg":     objs.KretprobeTcpSendmsg,
		"tcp_recvmsg":     objs.KretprobeTcpRecvmsg,
		//"tcp_cleanup_rbuf": objs.KretprobeTcpCleanupRbpf,
		//"inet_bind":        objs.KretprobeInetBind,
		"ip_make_skb":     objs.KretprobeIpMakeSkb,
		"udp_sendmsg":     objs.KretprobeUdpSendmsg,
		"udp_recvmsg":     objs.KretprobeUdpRecvmsg,
		"ip6_make_skb":    objs.KretprobeIp6MakeSkb,
		"udpv6_sendmsg":   objs.KretprobeUdpv6Sendmsg,
		"udpv6_recvmsg":   objs.KretprobeUdpv6Recvmsg,
		"skb_consume_udp": objs.KretprobeSkbConsumeUdp,
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

	// TODO 개선 필요
	go checkTime(intervalTime, objs, onewayClient)
	go logCheckTime(intervalTime, objs)

	<-stopper
}
