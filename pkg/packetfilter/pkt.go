package packetfilter

import (
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
)

const filterProgramPath = "/sys/fs/bpf/kubeshark/packet_filter"

type EBPF struct {
	attachBpfFunc  func(int32) error
	programWatcher *fsnotify.Watcher
}

func NewEBPF(attachBpfFunc func(int32) error) (*EBPF, error) {
	e := EBPF{
		attachBpfFunc: attachBpfFunc,
	}
	var err error
	if err = e.watchProgramChange(); err != nil {
		return nil, err
	}
	for {
		err = e.attachEbpfProgram()
		if err != nil {
			log.Error().Err(err).Msg("Attach program error:")
			time.Sleep(100 * time.Millisecond)
			continue
		} else {
			break
		}
	}

	return &e, err
}

func (e *EBPF) attachEbpfProgram() error {
	program, err := ebpf.LoadPinnedProgram(filterProgramPath, nil)
	if err != nil {
		return err
	}
	err = e.attachBpfFunc(int32(program.FD()))
	if err != nil {
		log.Info().Msg("Filter progrma is attached")
	}
	return err
}

func (e *EBPF) watchProgramChange() (err error) {
	e.programWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.Error().Err(err).Msg("Error create fsnotify watcher:")
		return
	}

	path := filepath.Dir(filterProgramPath)
	log.Info().Str("directory", path).Msg("Watching")
	err = e.programWatcher.Add(path)
	if err != nil {
		return
	}

	go func() {
		for {
			select {
			case event, ok := <-e.programWatcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Create) {
					if event.Name == filterProgramPath {
						err = e.attachEbpfProgram()
						if err != nil {
							log.Error().Err(err).Msg("Attach eBPF program failed:")
						}
					}
				}
			case err, ok := <-e.programWatcher.Errors:
				if !ok {
					return
				}
				log.Error().Err(err).Msg("watcher error:")
			}
		}
	}()

	return
}

func (e *EBPF) Close() error {
	if e.programWatcher != nil {
		return e.programWatcher.Close()
	}
	return nil
}
