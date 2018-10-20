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
	ifreqSock    *os.File
	netlink      netlink.Link
	nativeFormat PayloadFormat
	outputFormat PayloadFormat
	hwAddr       net.HardwareAddr
}

func (c *TunTapConfig) Create() (Tunnel, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}

	ifreq := &ifreq_flags{}
	if c.AllowNameSuffix && strings.HasSuffix(c.NameHint, "0") {
		if len(c.NameHint)+2 < unix.IFNAMSIZ {
			copy(ifreq.ifr_name[:], c.NameHint[:len(c.NameHint)-1]+"%d")
		} else {
			copy(ifreq.ifr_name[:], c.NameHint[:unix.IFNAMSIZ-3]+"%d")
		}
	} else {
		copy(ifreq.ifr_name[:], c.NameHint)
	}
	switch c.PreferredNativeFormat {
	case FormatIP:
		ifreq.ifr_flags = _IFF_TUN | c.ExtraFlags
	case FormatEthernet:
		ifreq.ifr_flags = _IFF_TAP | c.ExtraFlags
	default:
		f.Close()
		return nil, UnsupportedProtocolError
	}
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), unix.TUNSETIFF, uintptr(unsafe.Pointer(ifreq)))
	if r1 != 0 {
		if errno, ok := err.(syscall.Errno); ok && (errno == syscall.EINVAL || errno == syscall.EBUSY) && c.AllowNameSuffix {
			newName := ""
			for i := len(c.NameHint); i != 0; i-- {
				if c.NameHint[i-1] < '0' || c.NameHint[i-1] > '9' {
					newName = c.NameHint[:i]
					break
				}
			}
			if len(newName) == 0 {
				if c.PreferredNativeFormat == FormatEthernet {
					copy(ifreq.ifr_name[:], "tap%d\x00")
				} else {
					copy(ifreq.ifr_name[:], "tun%d\x00")
				}
			} else if len(newName)+3 < unix.IFNAMSIZ {
				copy(ifreq.ifr_name[:], newName+"%d\x00")
			} else {
				copy(ifreq.ifr_name[:], newName[:unix.IFNAMSIZ-3]+"%d\x00")
			}
			r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), unix.TUNSETIFF, uintptr(unsafe.Pointer(ifreq)))
			if r1 != 0 {
				f.Close()
				return nil, os.NewSyscallError("ioctl (TUNSETIFF)", err)
			}
		} else {
			f.Close()
			return nil, os.NewSyscallError("ioctl (TUNSETIFF)", err)
		}
	}
	name := string(bytes.SplitN(ifreq.ifr_name[:], []byte{0}, 2)[0])

	ifreqSock, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		f.Close()
		return nil, os.NewSyscallError("socket", err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		syscall.Close(ifreqSock)
		f.Close()
		return nil, err
	}

	t := &TunTapImpl{
		f:            f,
		ifreqSock:    os.NewFile(uintptr(ifreqSock), ""),
		netlink:      link,
		nativeFormat: c.PreferredNativeFormat,
	}
	return t, nil
}

func (t *TunTapImpl) AddIPAddresses(addresses []*IPAddress) (int, error) {
	for i, addr := range addresses {
		a := &netlink.Addr{
			IPNet: addr.Net,
			Peer:  addr.Peer,
		}
		err := netlink.AddrAdd(t.netlink, a)
		if err != nil {
			return i, err
		}
	}
	return len(addresses), nil
}

func (t *TunTapImpl) Close() error {
	_ = t.ifreqSock.Close()
	return t.f.Close()
}

func (t *TunTapImpl) MTU() (int, error) {
	// Use the ioctl method instead of the netlink method because it saves time
	name, err := t.Name()
	if err != nil {
		return DefaultMTU, err
	}
	ifreq := &ifreq_mtu{}
	copy(ifreq.ifr_name[:], name)
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, t.ifreqSock.Fd(), unix.SIOCGIFMTU, uintptr(unsafe.Pointer(ifreq)))
	if r1 != 0 {
		return DefaultMTU, os.NewSyscallError("ioctl (SIOCGIFMTU)", err)
	}
	return int(ifreq.ifr_mtu), nil
}

func (t *TunTapImpl) Name() (string, error) {
	ifreq := &ifreq_flags{}
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, t.f.Fd(), unix.TUNGETIFF, uintptr(unsafe.Pointer(ifreq)))
	if r1 != 0 {
		return "", os.NewSyscallError("ioctl (TUNGETIFF)", err)
	}
	name := string(bytes.SplitN(ifreq.ifr_name[:], []byte{0}, 2)[0])
	return name, nil
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
	err := netlink.LinkSetUp(t.netlink)
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
	ifreq := &ifreq_mtu{}
	name, err := t.Name()
	if err != nil {
		return err
	}
	copy(ifreq.ifr_name[:], name)
	ifreq.ifr_mtu = int32(mtu)
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, t.ifreqSock.Fd(), unix.SIOCSIFMTU, uintptr(unsafe.Pointer(ifreq)))
	if r1 != 0 {
		return os.NewSyscallError("ioctl (SIOCSIFMTU)", err)
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
