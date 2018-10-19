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

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type TunTapImpl struct {
	f            *os.File
	linkIndex    int
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
		copy(ifr.ifr_name[:], c.NameHint[:len(c.NameHint)-1][:unix.IFNAMSIZ-2]+"%i")
	} else {
		copy(ifr.ifr_name[:], c.NameHint)
	}
	switch c.PreferredNativeFormat {
	case FormatIP:
		ifr.ifr_flags = _IFF_TUN
	case FormatEthernet:
		ifr.ifr_flags = _IFF_TAP
	default:
		f.Close()
		return nil, UnsupportedProtocolError
	}
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), unix.TUNSETIFF, uintptr(unsafe.Pointer(ifr)))
	if r1 != 0 {
		f.Close()
		return nil, err
	}
	name := string(bytes.SplitN(ifr.ifr_name[:], []byte{0}, 2)[0])
	link, err := netlink.LinkByName(name)
	if err != nil {
		f.Close()
		return nil, err
	}
	t := &TunTapImpl{
		f:            f,
		linkIndex:    link.Attrs().Index,
		nativeFormat: c.PreferredNativeFormat,
	}
	return t, nil
}

func (t *TunTapImpl) AddIPAddresses(addresses []*IPAddress) (int, error) {
	link, err := netlink.LinkByIndex(t.linkIndex)
	if err != nil {
		return 0, err
	}
	for i, addr := range addresses {
		a := &netlink.Addr{
			IPNet: addr.Net,
			Peer:  addr.Peer,
		}
		err = netlink.AddrAdd(link, a)
		if err != nil {
			return i, err
		}
	}
	return len(addresses), nil
}

func (t *TunTapImpl) Close() error {
	return t.f.Close()
}

func (t *TunTapImpl) MTU() (int, error) {
	link, err := netlink.LinkByIndex(t.linkIndex)
	if err != nil {
		return DefaultMTU, err
	}
	return link.Attrs().MTU, nil
}

func (t *TunTapImpl) Name() (string, error) {
	link, err := netlink.LinkByIndex(t.linkIndex)
	if err != nil {
		return "", err
	}
	return link.Attrs().Name, nil
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
	link, err := netlink.LinkByIndex(t.linkIndex)
	if err != nil {
		return err
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return err
	}
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
	link, err := netlink.LinkByIndex(t.linkIndex)
	if err != nil {
		return err
	}
	err = netlink.LinkSetMTU(link, mtu)
	if err != nil {
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
