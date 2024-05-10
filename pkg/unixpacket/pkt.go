package unixpacket

import (
	"unsafe"
)

type PacketDirection uint8

const (
	PacketRecived PacketDirection = 0
	PacketSent    PacketDirection = 1
)

const PacketHeaderSize = int(unsafe.Sizeof(PacketUnixSocketHeader{}))

type PacketUnixSocketHeader struct {
	PacketCounter uint64
	Timestamp     uint64
	CgroupID      uint64
	Direction     PacketDirection
}

type PacketUnixSocket []byte

func (pkt *PacketUnixSocket) GetHeader() *PacketUnixSocketHeader {
	data := []byte(*pkt)
	return (*PacketUnixSocketHeader)(unsafe.Pointer(&data[0]))
}

func (pkt *PacketUnixSocket) GetData() []byte {
	data := []byte(*pkt)
	return data[PacketHeaderSize:]
}
