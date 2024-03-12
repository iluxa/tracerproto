package packetfilter

import (
	"fmt"
	"os"
	"path"

	"github.com/cilium/ebpf"
)

const bpfDir = "/sys/fs/bpf/kubeshark"

func GetProgramFilterPath() (p string, err error) {
	if err = os.MkdirAll(bpfDir, 0666); err != nil {
		return
	}
	p = path.Join(bpfDir, "packet_filter")
	return
}

func GeBPFProgArrayPath() (p string, err error) {
	if err = os.MkdirAll(bpfDir, 0644); err != nil {
		return
	}
	p = path.Join(bpfDir, "bpf_progs")
	return
}

type EBPF struct {
	filterProgram *ebpf.Program
	bpfProgArray  *ebpf.Map
}

func NewEBPF() (*EBPF, error) {
	p, err := GetProgramFilterPath()
	if err != nil {
		return nil, fmt.Errorf("get program failed: %v", err)
	}
	program, err := ebpf.LoadPinnedProgram(p, nil)
	if err != nil {
		return nil, fmt.Errorf("load pinned program failed: %v", err)
	}
	return &EBPF{
		filterProgram: program,
	}, nil
}

func (pf *EBPF) GetFilterProgramFD() int32 {
	return int32(pf.filterProgram.FD())
}

func (pf *EBPF) SetEBPF(cbpfProgram string) error {
	// TODO
	return nil
}

func (pf *EBPF) Close() error {
	if pf.filterProgram != nil {
		return pf.filterProgram.Close()
	}
	return nil
}
