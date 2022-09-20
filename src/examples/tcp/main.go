package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

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

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags -O2 -type nKey -type statusValue bpf tcp.c -- -I../headers

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
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

	/*link, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.TcpClose,
	})
	*/

	link1, err := link.Kprobe("tcp_connect", objs.KprobeTcpConnect, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	defer link1.Close()

	link2, err := link.Kretprobe("tcp_connect", objs.KretprobeTcpConnect, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	defer link2.Close()

	link3, err := link.Kprobe("inet_csk_accept", objs.KprobeInetCskAccept, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	defer link3.Close()

	link4, err := link.Kretprobe("inet_csk_accept", objs.KretprobeInetCskAccept, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	defer link4.Close()

	link5, err := link.Kprobe("tcp_set_state", objs.KprobeTcpSetState, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	defer link5.Close()
	link6, err := link.Kprobe("tcp_sendmsg", objs.KprobeTcpSendmsg, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	defer link6.Close()

	link7, err := link.Kretprobe("tcp_sendmsg", objs.KretprobeTcpSendmsg, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	defer link7.Close()
	link8, err := link.Kprobe("tcp_cleanup_rbuf", objs.KprobeTcpCleanupRbpf, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	defer link8.Close()

	link9, err := link.Kretprobe("tcp_cleanup_rbuf", objs.KretprobeTcpCleanupRbpf, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	defer link9.Close()

	link10, err := link.Kprobe("tcp_close", objs.KprobeTcpClose, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	defer link10.Close()
	// Wait

	go func() {
		for {
			time.Sleep(time.Second * 1)
			var key bpfNKey
			var value bpfStatusValue

			iter := objs.StatusMap.Iterate()
			for {
				ret := iter.Next(&key, &value)
				if ret {
					fmt.Println(key, value)
					value.CheckFlag += 1
					if value.Status != 7 {
						//objs.StatusMap.Update(key, value, ebpf.UpdateAny)
					} else {
						objs.StatusMap.Delete(key)
					}
				} else {
					break
				}
			}

		}
	}()

	<-stopper
}
