// +build darwin

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
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type TunTapImpl struct {
	f            *os.File
	ifreqSock    *os.File
	ifreqSockIn6 *os.File
	outputFormat PayloadFormat
	hwAddr       net.HardwareAddr
	buffer       chan *Packet
}

func (c *TunTapConfig) Create() (Tunnel, error) {
	fd, err := syscall.Socket(_PF_SYSTEM, syscall.SOCK_DGRAM, _SYSPROTO_CONTROL)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}

	err = syscall.SetNonblock(fd, true)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	syscall.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), "")

	info := &ctl_info{}
	copy(info.ctl_name[:], "com.apple.net.utun_control")
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), _CTLIOCGINFO, uintptr(unsafe.Pointer(info)))
	if r1 != 0 {
		f.Close()
		return nil, os.NewSyscallError("ioctl (CTLIOCGINFO)", err)
	}

	sc := &sockaddr_ctl{
		sc_len:     uint8(unsafe.Sizeof(sockaddr_ctl{})),
		sc_family:  syscall.AF_SYSTEM,
		ss_sysaddr: _AF_SYS_CONTROL,
		sc_id:      info.ctl_id,
		sc_unit:    0,
	}

	var utunID int32
	if n, _ := fmt.Sscanf(c.NameHint, "utun%d", &utunID); n == 1 {
		sc.sc_unit = uint32(utunID + 1)
	}

	r1, _, err = syscall.Syscall(syscall.SYS_CONNECT, f.Fd(), uintptr(unsafe.Pointer(sc)), unsafe.Sizeof(*sc))
	if r1 != 0 {
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.EBUSY && c.AllowNameSuffix {
			sc.sc_unit = 0
			r1, _, err = syscall.Syscall(syscall.SYS_CONNECT, f.Fd(), uintptr(unsafe.Pointer(sc)), unsafe.Sizeof(*sc))
			if r1 != 0 {
				return nil, os.NewSyscallError("connect", err)
			}
		} else {
			return nil, os.NewSyscallError("connect", err)
		}
	}

	if c.ExtraFlags != 0 {
		extraFlags := uint32(c.ExtraFlags)
		r1, _, err := syscall.Syscall6(syscall.SYS_SETSOCKOPT, f.Fd(), _SYSPROTO_CONTROL, _UTUN_OPT_FLAGS, uintptr(unsafe.Pointer(&extraFlags)), unsafe.Sizeof(extraFlags), 0)
		if r1 != 0 {
			f.Close()
			return nil, os.NewSyscallError("setsockopt", err)
		}
	}

	ifreqSock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		f.Close()
		return nil, os.NewSyscallError("socket", err)
	}
	ifreqSockIn6, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		syscall.Close(ifreqSock)
		f.Close()
		return nil, os.NewSyscallError("socket", err)
	}

	t := &TunTapImpl{
		f:            f,
		ifreqSock:    os.NewFile(uintptr(ifreqSock), ""),
		ifreqSockIn6: os.NewFile(uintptr(ifreqSockIn6), ""),
		buffer:       make(chan *Packet, DefaultPostProcessBufferSize),
	}
	return t, nil
}

func (t *TunTapImpl) AddIPAddresses(addresses []*IPAddress) (int, error) {
	name, err := t.Name()
	if err != nil {
		return 0, err
	}

	for i, addr := range addresses {
		if addr.Net == nil {
			return i, errors.New("gophertun: invalid IP address: <nil>")
		}
		addrNet := simplifyIPNet(*addr.Net)
		if addrNet == nil {
			return i, fmt.Errorf("gophertun: invalid IP address: %s", *addr.Net)
		}

		addrPeer := addrNet
		if addr.Peer != nil {
			addrPeer = simplifyIPNet(*addr.Peer)
			if addrPeer == nil {
				return i, fmt.Errorf("gophertun: invalid IP peer: %s", *addr.Peer)
			}
		}

		if len(addrNet.IP) == 4 && len(addrPeer.IP) == 4 {
			ifreq := &ifaliasreq{}
			copy(ifreq.ifra_name[:], name)
			ifreq.ifra_addr.sin_len = uint8(unsafe.Sizeof(ifreq.ifra_addr))
			ifreq.ifra_addr.sin_family = syscall.AF_INET
			copy(ifreq.ifra_addr.sin_addr[:], addrNet.IP)
			ifreq.ifra_broadaddr.sin_len = uint8(unsafe.Sizeof(ifreq.ifra_broadaddr))
			ifreq.ifra_broadaddr.sin_family = syscall.AF_INET
			copy(ifreq.ifra_broadaddr.sin_addr[:], addrPeer.IP)
			ifreq.ifra_mask.sin_len = uint8(unsafe.Sizeof(ifreq.ifra_mask))
			ifreq.ifra_mask.sin_family = syscall.AF_INET
			copy(ifreq.ifra_mask.sin_addr[:], addrPeer.Mask)

			r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, t.ifreqSock.Fd(), unix.SIOCAIFADDR, uintptr(unsafe.Pointer(ifreq)))
			if r1 != 0 {
				return i, os.NewSyscallError("ioctl (SIOCAIFADDR)", err)
			}
		} else {
			addrNet = ipnetTo16(*addr.Net)
			if addrNet == nil {
				return i, fmt.Errorf("gophertun: invalid IP address: %s", *addr.Net)
			}
			if addr.Peer != nil {
				addrPeer = ipnetTo16(*addr.Peer)
				if addrPeer == nil {
					return i, fmt.Errorf("gophertun: invalid IP peer: %s", *addr.Peer)
				}
			} else {
				addrPeer = addrNet
			}

			ifreq := &in6_aliasreq{}
			copy(ifreq.ifra_name[:], name)
			ifreq.ifra_addr.sin6_len = uint8(unsafe.Sizeof(ifreq.ifra_addr))
			ifreq.ifra_addr.sin6_family = syscall.AF_INET6
			copy(ifreq.ifra_addr.sin6_addr[:], addrNet.IP)
			if bytes.Equal(addrPeer.Mask, net.CIDRMask(128, 128)) {
				ifreq.ifra_dstaddr.sin6_len = uint8(unsafe.Sizeof(ifreq.ifra_dstaddr))
				ifreq.ifra_dstaddr.sin6_family = syscall.AF_INET6
				copy(ifreq.ifra_dstaddr.sin6_addr[:], addrPeer.IP)
			}
			ifreq.ifra_prefixmask.sin6_len = uint8(unsafe.Sizeof(ifreq.ifra_prefixmask))
			ifreq.ifra_prefixmask.sin6_family = syscall.AF_INET6
			copy(ifreq.ifra_prefixmask.sin6_addr[:], addrPeer.Mask)
			ifreq.ia6t_vltime = _ND6_INFINITE_LIFETIME
			ifreq.ia6t_pltime = _ND6_INFINITE_LIFETIME

			r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, t.ifreqSockIn6.Fd(), _SIOCAIFADDR_IN6, uintptr(unsafe.Pointer(ifreq)))
			if r1 != 0 {
				return i, os.NewSyscallError("ioctl (SIOCAIFADDR_IN6)", err)
			}
		}
	}
	return len(addresses), nil
}

func (t *TunTapImpl) Close() error {
	_ = t.ifreqSockIn6.Close()
	_ = t.ifreqSock.Close()
	return t.f.Close()
}

func (t *TunTapImpl) MTU() (int, error) {
	ifreq := &ifreq_mtu{}
	name, err := t.Name()
	if err != nil {
		return DefaultMTU, err
	}
	copy(ifreq.ifr_name[:], name)
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, t.f.Fd(), unix.SIOCGIFMTU, uintptr(unsafe.Pointer(ifreq)))
	if r1 != 0 {
		return DefaultMTU, os.NewSyscallError("ioctl (SIOCGIFMTU)", err)
	}
	return int(ifreq.ifr_mtu), nil
}

func tuntapName(fd uintptr) (string, error) {
	var ifName [unix.IFNAMSIZ]byte
	ifNameLen := uintptr(len(ifName))
	r1, _, err := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, _SYSPROTO_CONTROL, _UTUN_OPT_IFNAME, uintptr(unsafe.Pointer(&ifName[0])), uintptr(unsafe.Pointer(&ifNameLen)), 0)
	if r1 != 0 {
		return "", os.NewSyscallError("getsockopt", err)
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
		return ErrUnsupportedFeature
	}
	t.hwAddr = generateMACAddress()

	name, err := t.Name()
	if err != nil {
		return err
	}

	ifreq := &ifreq_flags{}
	copy(ifreq.ifr_name[:], name)
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, t.f.Fd(), unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(ifreq)))
	if r1 != 0 {
		return os.NewSyscallError("ioctl (SIOCGIFFLAGS)", err)
	}
	ifreq.ifr_flags |= syscall.IFF_UP
	r1, _, err = syscall.Syscall(syscall.SYS_IOCTL, t.f.Fd(), unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(ifreq)))
	if r1 != 0 {
		return os.NewSyscallError("ioctl (SIOCSIFFLAGS)", err)
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
	select {
	case p := <-t.buffer:
		return p, nil
	default:
		return readCook(t.readRaw, t.writeRaw, t.hwAddr, t.buffer)
	}
}

func (t *TunTapImpl) readRaw() (*Packet, error) {
	buf := make([]byte, DefaultMRU+4)
retry:
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
		Format:    FormatIP,
		EtherType: etherType,
		Payload:   buf[4:n],
		Extra:     buf[:4],
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
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, t.f.Fd(), unix.SIOCSIFMTU, uintptr(unsafe.Pointer(ifreq)))
	if r1 != 0 {
		return os.NewSyscallError("ioctl (SIOCSIFMTU)", err)
	}
	return nil
}

func (t *TunTapImpl) Write(packet *Packet, pmtud bool) error {
	if pmtud {
		return writeCook(t.writeRaw, packet, t.MTU, t.hwAddr, t.buffer)
	}
	return writeCook(t.writeRaw, packet, nil, t.hwAddr, t.buffer)
}

func (t *TunTapImpl) writeRaw(packet *Packet) (needFrag bool, err error) {
	packet, err = packet.ConvertTo(FormatIP, nil)
	if err != nil {
		return false, err
	}
	if packet == nil {
		return false, nil
	}
	buf := make([]byte, len(packet.Payload)+4)
	switch packet.EtherType {
	case EtherTypeIPv4:
		binary.BigEndian.PutUint32(buf[:4], syscall.AF_INET)
	case EtherTypeIPv6:
		binary.BigEndian.PutUint32(buf[:4], syscall.AF_INET6)
	default:
		return false, nil
	}
	copy(buf[4:], packet.Payload)
	_, err = t.f.Write(buf)
	if err != nil {
		return false, err
	}
	return false, nil
}
