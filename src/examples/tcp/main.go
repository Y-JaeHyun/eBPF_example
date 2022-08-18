package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags -O2 bpf tcp.c -- -I../headers

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	/*link, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.TcpClose,
	})
	*/

	link1, err := link.Kprobe("tcp_v4_connect", objs.KprobeTcpV4Connect, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer link1.Close()

	link2, err := link.Kretprobe("tcp_v4_connect", objs.KretprobeTcpV4Connect, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer link2.Close()

	link3, err := link.Kprobe("tcp_close", objs.KprobeTcpClose, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer link3.Close()

	link4, err := link.Kretprobe("inet_csk_accept", objs.KretprobeInetCskAccept, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer link4.Close()

	link5, err := link.Kprobe("inet_csk_accept", objs.KprobeInetCskAccept, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer link5.Close()

	link6, err := link.Kprobe("tcp_set_state", objs.KprobeTcpSetState, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer link6.Close()

	link7, err := link.Kprobe("tcp_sendmsg", objs.KprobeTcpSendmsg, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	defer link7.Close()

	link8, err := link.Kretprobe("tcp_sendmsg", objs.KretprobeTcpSendmsg, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	defer link8.Close()
	// Wait

	<-stopper
}
