// +build linux

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
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

type TunTapImpl struct {
	f            *os.File
	name         string
	nativeFormat PayloadFormat
	outputFormat PayloadFormat
	hwAddr       net.HardwareAddr
}

const (
	_IF_NAMESIZE     = 16
	_IFF_TUN         = 0x0001
	_IFF_TAP         = 0x0002
	_IFF_MULTI_QUEUE = 0x0100
)

type (
	ifreq_addr struct {
		ifr_name  [_IF_NAMESIZE]byte
		ifru_addr syscall.RawSockaddr
	}
	ifreq_mtu struct {
		ifr_name [_IF_NAMESIZE]byte
		ifru_mtu int32
		_        [28 - _IF_NAMESIZE]byte
	}
	ifreq_flags struct {
		ifr_name   [_IF_NAMESIZE]byte
		ifru_flags int16
	}
)

var (
	_TUNSETIFF          = _IOW('T', 202, 4)
	_SIOCGIFMTU uintptr = 0x8921
	_SIOCSIFMTU uintptr = 0x8922
)

func (c *TunTapConfig) Create() (Tunnel, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}
	ifr := &ifreq_flags{}
	if c.AllowNameSuffix && strings.HasSuffix(c.NameHint, "0") {
		copy(ifr.ifr_name[:], c.NameHint[:len(c.NameHint)-1][:_IF_NAMESIZE-2]+"%i")
	} else {
		copy(ifr.ifr_name[:], c.NameHint)
	}
	switch c.PreferredNativeFormat {
	case FormatIP:
		ifr.ifru_flags = _IFF_TUN
	case FormatEthernet:
		ifr.ifru_flags = _IFF_TUN
	default:
		return nil, UnsupportedProtocolError
	}
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), _TUNSETIFF, uintptr(unsafe.Pointer(ifr)))
	if r1 != 0 {
		return nil, err
	}
	name := string(bytes.SplitN(ifr.ifr_name[:], []byte{0}, 2)[0])
	t := &TunTapImpl{
		f:            f,
		name:         name,
		nativeFormat: c.PreferredNativeFormat,
	}
	return t, nil
}

func (t *TunTapImpl) Close() error {
	return t.f.Close()
}

func (t *TunTapImpl) MTU() (int, error) {
	ifreq := &ifreq_mtu{}
	name, err := t.Name()
	if err != nil {
		return DefaultMTU, err
	}
	copy(ifreq.ifr_name[:], name)
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, t.f.Fd(), _SIOCGIFMTU, uintptr(unsafe.Pointer(ifreq)))
	if r1 != 0 {
		return DefaultMTU, err
	}
	return int(ifreq.ifru_mtu), nil
}

func (t *TunTapImpl) Name() (string, error) {
	return t.name, nil
}

func (t *TunTapImpl) NativeFormat() PayloadFormat {
	return t.nativeFormat
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
	buf := make([]byte, DefaultMRU+4)
retry:
	n, err := t.f.Read(buf[:])
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	packet := &Packet{
		Format:  t.nativeFormat,
		Proto:   EtherType(binary.BigEndian.Uint16(buf[2:4])),
		Payload: buf[4:n],
		Extra:   buf[:2],
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
	ifreq := &ifreq_mtu{}
	name, err := t.Name()
	if err != nil {
		return err
	}
	copy(ifreq.ifr_name[:], name)
	ifreq.ifru_mtu = int32(mtu)
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, t.f.Fd(), _SIOCSIFMTU, uintptr(unsafe.Pointer(ifreq)))
	if r1 != 0 {
		return err
	}
	return nil
}

func (t *TunTapImpl) Write(packet *Packet) error {
	packet, err := packet.ConvertTo(t.outputFormat, t.hwAddr)
	if err != nil {
		return err
	}
	if packet == nil {
		return nil
	}
	buf := make([]byte, len(packet.Payload)+4)
	copy(buf[:2], packet.Extra)
	binary.BigEndian.PutUint16(buf[2:4], uint16(packet.Proto))
	copy(buf[4:], packet.Payload)
	_, err = t.f.Write(buf)
	if err != nil {
		return err
	}
	return nil
}
