package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	// Load precompiled BPF object file
	spec, err := ebpf.LoadCollectionSpec("exec_monitor.bpf.o")
	if err != nil {
		log.Fatalf("failed to load BPF program: %v", err)
	}

	objs := struct {
		TraceExecve *ebpf.Program `ebpf:"trace_execve"`
	}{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("failed to assign BPF objects: %v", err)
	}

	// Attach to execve syscall tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	log.Println("eBPF program running. Press Ctrl+C to exit.")

	// Wait for interrupt signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	log.Println("Exiting...")
}
