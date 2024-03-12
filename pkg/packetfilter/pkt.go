package packetfilter

import (
	"github.com/cilium/ebpf"
	"os"
	"path"
	"syscall"
)

func GetProgramFilterPath() (p string, err error) {
	const bpfDir = "/sys/fs/bpf/kubeshark"

	if err = os.MkdirAll(bpfDir, 0644); err != nil {
		return
	}
	p = path.Join(bpfDir, "packets_buffer")
	return
}

func OpenFilter() (int32, error) {
	p, err := GetProgramFilterPath()
	if err != nil {
		return -1, err
	}
	program, err := ebpf.LoadPinnedProgram(p, nil)
	if err != nil {
		return -1, err
	}
	return int32(program.FD()), nil
}

func CloseFilter(fd int32) error {
	if fd != -1 {
		syscall.Close(int(fd))
	}
	return nil
}
