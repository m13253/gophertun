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
	netlink      net.PacketConn
	nativeFormat PayloadFormat
	outputFormat PayloadFormat
	hwAddr       net.HardwareAddr
}

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
		ifr.ifr_flags = _IFF_TUN
	case FormatEthernet:
		ifr.ifr_flags = _IFF_TAP
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
	name, err := t.Name()
	if err != nil {
		return DefaultMTU, err
	}

	sock, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return DefaultMTU, err
	}
	defer syscall.Close(sock)

	ifreq := &ifreq_mtu{}
	copy(ifreq.ifr_name[:], name)
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), _SIOCGIFMTU, uintptr(unsafe.Pointer(ifreq)))
	if r1 != 0 {
		return DefaultMTU, err
	}
	return int(ifreq.ifr_mtu), nil
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
		Format:    t.nativeFormat,
		EtherType: EtherType(binary.BigEndian.Uint16(buf[2:4])),
		Payload:   buf[4:n],
		Extra:     buf[:2],
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
	name, err := t.Name()
	if err != nil {
		return err
	}

	sock, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(sock)

	ifreq := &ifreq_mtu{}
	copy(ifreq.ifr_name[:], name)
	ifreq.ifr_mtu = int32(mtu)
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), _SIOCSIFMTU, uintptr(unsafe.Pointer(ifreq)))
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
	binary.BigEndian.PutUint16(buf[2:4], uint16(packet.EtherType))
	copy(buf[4:], packet.Payload)
	_, err = t.f.Write(buf)
	if err != nil {
		return err
	}
	return nil
}
