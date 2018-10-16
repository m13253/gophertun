/*
  MIT License

  Copyright (c) 2018 Star Brilliant

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/

package gophertun

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

type TunTapImpl struct {
	f            *os.File
	outputFormat PayloadFormat
	hwAddr       net.HardwareAddr
}

const (
	_PF_SYSTEM        = syscall.AF_SYSTEM
	_SYSPROTO_CONTROL = 2
	_AF_SYS_CONTROL   = 2
	_UTUN_OPT_IFNAME  = 2
)

type ctl_info struct {
	ctl_id   uint32
	ctl_name [96]byte
}

var _CTLIOCGINFO = 0xc0004e03 | (unsafe.Sizeof(ctl_info{}) & 0x3fff << 16)

type sockaddr_ctl struct {
	sc_len      uint8
	sc_family   uint8
	ss_sysaddr  uint16
	sc_id       uint32
	sc_unit     uint32
	sc_reserved [5]uint32
}

func (c *TunTapConfig) Create() (Tunnel, error) {
	fd, err := syscall.Socket(syscall.AF_SYSTEM, syscall.SOCK_DGRAM, _SYSPROTO_CONTROL)
	if err != nil {
		return nil, err
	}

	info := &ctl_info{}
	copy(info.ctl_name[:], "com.apple.net.utun_control")
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), _CTLIOCGINFO, uintptr(unsafe.Pointer(info)))
	if r1 != 0 {
		return nil, err
	}

	sc := &sockaddr_ctl{
		sc_len:     uint8(unsafe.Sizeof(sockaddr_ctl{})),
		sc_family:  syscall.AF_SYSTEM,
		ss_sysaddr: _AF_SYS_CONTROL,
		sc_id:      info.ctl_id,
		sc_unit:    0,
	}

	var utunID uint32
	if n, _ := fmt.Sscanf(c.NameHint, "utun%d", &utunID); n == 1 {
		sc.sc_unit = utunID + 1
	}

	r1, _, err = syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(sc)), unsafe.Sizeof(*sc))
	if r1 != 0 {
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.EBUSY && c.AllowNameSuffix {
			sc.sc_unit = 0
			r1, _, err = syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(sc)), unsafe.Sizeof(*sc))
			if r1 != 0 {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	name, err := tuntapName(uintptr(fd))
	if err != nil {
		return nil, err
	}

	err = syscall.SetNonblock(fd, true)
	if err != nil {
		return nil, err
	}

	f := os.NewFile(uintptr(fd), "/dev/net/"+name)

	t := &TunTapImpl{
		f: f,
	}

	return t, nil
}

func (t *TunTapImpl) Close() error {
	return t.f.Close()
}

func (t *TunTapImpl) MTU() (int, error) {
	return DefaultMTU, nil
}

func tuntapName(fd uintptr) (string, error) {
	var ifName [15]byte // 15 is enough for "utun4294967295"
	ifNameLen := uintptr(len(ifName))
	r1, _, err := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, _SYSPROTO_CONTROL, _UTUN_OPT_IFNAME, uintptr(unsafe.Pointer(&ifName[0])), uintptr(unsafe.Pointer(&ifNameLen)), 0)
	if r1 != 0 {
		return "", err
	}
	return string(ifName[:ifNameLen-1]), nil
}

func (t *TunTapImpl) Name() (string, error) {
	return tuntapName(t.f.Fd())
}

func (t *TunTapImpl) NativeFormat() PayloadFormat {
	return FormatIP
}

func (t *TunTapImpl) Open(outputFormat PayloadFormat) error {
	switch outputFormat {
	case FormatUnknown, FormatIP:
		t.outputFormat = FormatIP
	case FormatEthernet:
		t.outputFormat = FormatEthernet
	default:
		return UnsupportedFeatureError
	}
	t.hwAddr = generateMACAddress()
	return nil
}

func (t *TunTapImpl) OutputFormat() PayloadFormat {
	return t.outputFormat
}

func (t *TunTapImpl) RawFile() *os.File {
	return t.f
}

func (t *TunTapImpl) Read() (*Packet, error) {
retry:
	buf := make([]byte, DefaultMRU+4)
	n, err := t.f.Read(buf[:])
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	etherType := EtherType(0)
	switch binary.BigEndian.Uint32(buf[:4]) {
	case syscall.AF_INET:
		etherType = EtherTypeIPv4
	case syscall.AF_INET6:
		etherType = EtherTypeIPv6
	}
	packet := &Packet{
		Format:  FormatIP,
		Proto:   etherType,
		Payload: buf[4:n],
		Extra:   buf[:4],
	}
	packet, err = packet.ConvertTo(t.outputFormat, t.hwAddr)
	if err != nil {
		return nil, err
	}
	if packet == nil {
		goto retry
	}
	return packet, nil
}

func (t *TunTapImpl) SetMTU(mtu int) error {
	return UnsupportedFeatureError
}

func (t *TunTapImpl) Write(packet *Packet) error {
	packet, err := packet.ConvertTo(FormatIP, nil)
	if err != nil {
		return err
	}
	if packet == nil {
		return nil
	}
	buf := make([]byte, len(packet.Payload)+4)
	switch packet.Proto {
	case EtherTypeIPv4:
		binary.BigEndian.PutUint32(buf[:4], syscall.AF_INET)
	case EtherTypeIPv6:
		binary.BigEndian.PutUint32(buf[:4], syscall.AF_INET6)
	default:
		return UnsupportedProtocolError
	}
	copy(buf[4:], packet.Payload)
	_, err = t.f.Write(buf)
	if err != nil {
		return err
	}
	return nil
}
