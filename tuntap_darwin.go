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
	"errors"
	"os"
	"syscall"
	"unsafe"
)

type TunTapImpl struct {
	f           *os.File
	convertType PayloadType
}

const (
	_PF_SYSTEM        = syscall.AF_SYSTEM
	_SYSPROTO_CONTROL = 2
	_AF_SYS_CONTROL   = 2
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
	if r1 == ^uintptr(0) {
		return nil, err
	}

	sc := &sockaddr_ctl{
		sc_len:     uint8(unsafe.Sizeof(sockaddr_ctl{})),
		sc_family:  syscall.AF_SYSTEM,
		ss_sysaddr: _AF_SYS_CONTROL,
		sc_id:      info.ctl_id,
		sc_unit:    0,
	}

	r1, _, err = syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(sc)), unsafe.Sizeof(*sc))
	if r1 == ^uintptr(0) {
		return nil, err
	}

	f := os.NewFile(uintptr(fd), "")

	t := &TunTapImpl{
		f: f,
	}

	return t, nil
}

func (t *TunTapImpl) Close() error {
	return t.f.Close()
}

func (t *TunTapImpl) GetMTU() (int, error) {
	return DefaultMTU, nil
}

func (t *TunTapImpl) GetNativeType() PayloadType {
	return PayloadIP
}

func (t *TunTapImpl) Open(convertType PayloadType) error {
	switch convertType {
	case PayloadUnknown, PayloadIP:
		t.convertType = PayloadIP
	case PayloadEthernet:
		t.convertType = PayloadEthernet
	default:
		return UnsupportedFeatureError
	}
	return nil
}

func (t *TunTapImpl) RawFile() *os.File {
	return t.f
}

func (t *TunTapImpl) Read() (*Packet, error) {
	switch t.convertType {
	case PayloadIP:
		buf := make([]byte, DefaultMRU)
		n, err := t.f.Read(buf[:])
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, nil
		}
		p := &Packet{
			Payload: buf[:n],
		}
		ipVersion := buf[0] >> 4
		switch ipVersion {
		case 4:
			p.Proto = 0x0800
		case 6:
			p.Proto = 0x86dd
		}
		return p, nil
	case PayloadEthernet:
		buf := make([]byte, DefaultMRU+14)
		n, err := t.f.Read(buf[14:])
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, nil
		}
		p := &Packet{
			Payload: buf[:n+14],
		}
		ipVersion := buf[14] >> 4
		switch ipVersion {
		case 4:
			p.Proto = 0x0800
		case 6:
			p.Proto = 0x86dd
		}
		return p, nil
	default:
		panic("gophertun: unsupported payload type")
	}
}

func (t *TunTapImpl) SetMTU(mtu int) error {
	return UnsupportedFeatureError
}

func (t *TunTapImpl) Write(packet *Packet) error {
	switch t.convertType {
	case PayloadIP:
		_, err := t.f.Write(packet.Payload)
		if err != nil {
			return err
		}
	case PayloadEthernet:
		if len(packet.Payload) < 14 {
			return errors.New("gophertun: incomplete ethernet frame")
		}
		etherType := (uint16(packet.Payload[12]) << 8) | uint16(packet.Payload[13])
		switch etherType {
		case 0x0800, 0x86dd: // IPv4, IPv6
			_, err := t.f.Write(packet.Payload[14:])
			if err != nil {
				return err
			}
		default:
			return nil
		}
	default:
		panic("gophertun: unsupported payload type")
	}
	return nil
}
