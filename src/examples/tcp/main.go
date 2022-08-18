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
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags -O2 -type key -type value bpf tcp.c -- -I../headers

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
		fmt.Println(err)
		log.Fatal(err)
	}
	defer link1.Close()

	link2, err := link.Kretprobe("tcp_v4_connect", objs.KretprobeTcpV4Connect, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	defer link2.Close()
	// Wait

	for {
		var key bpfKey
		var value bpfValue

		iter := objs.MatrixMap.Iterate()
		ret := iter.Next(&key, &value)

		if ret {
			fmt.Println(key, value)
		}
	}

	<-stopper
}
