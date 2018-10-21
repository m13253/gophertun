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
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	_PF_SYSTEM             = syscall.AF_SYSTEM
	_SYSPROTO_CONTROL      = 2
	_AF_SYS_CONTROL        = 2
	_UTUN_OPT_FLAGS        = 1
	_UTUN_OPT_IFNAME       = 2
	_ND6_INFINITE_LIFETIME = int32(-1)
)

type (
	ctl_info struct {
		ctl_id   uint32
		ctl_name [96]byte
	}
	ifreq_flags struct {
		ifr_name  [unix.IFNAMSIZ]byte
		ifr_flags int16
		_         int16
		_         [28 - unix.IFNAMSIZ]byte
	}
	ifreq_mtu struct {
		ifr_name [unix.IFNAMSIZ]byte
		ifr_mtu  int32
		_        [28 - unix.IFNAMSIZ]byte
	}
	ifaliasreq struct {
		ifra_name      [unix.IFNAMSIZ]byte
		ifra_addr      sockaddr_in
		ifra_broadaddr sockaddr_in
		ifra_mask      sockaddr_in
	}
	in6_aliasreq struct {
		ifra_name       [unix.IFNAMSIZ]byte
		ifra_addr       sockaddr_in6
		ifra_dstaddr    sockaddr_in6
		ifra_prefixmask sockaddr_in6
		ifra_flags      int32
		ia6t_expire     int64 // time_t
		ia6t_preferred  int64 // time_t
		ia6t_vltime     int32
		ia6t_pltime     int32
	}
	sockaddr_ctl struct {
		sc_len      uint8
		sc_family   uint8
		ss_sysaddr  uint16
		sc_id       uint32
		sc_unit     uint32
		sc_reserved [5]uint32
	}
	sockaddr_in struct {
		sin_len    uint8
		sin_family uint8
		sin_port   uint16
		sin_addr   [4]byte
		sin_zero   [8]byte
	}
	sockaddr_in6 struct {
		sin6_len      uint8
		sin6_family   uint8
		sin6_port     uint16
		sin6_flowinfo uint32
		sin6_addr     [16]byte
		sin6_scope_id uint32
	}
)

var (
	_CTLIOCGINFO     = _IOWR('N', 3, unsafe.Sizeof(ctl_info{}))
	_SIOCAIFADDR_IN6 = _IOW('i', 26, unsafe.Sizeof(in6_aliasreq{}))
)

func _IO(group, num uint8) uintptr {
	return (uintptr(group) << 8) | uintptr(num)
}

func _IOR(group, num uint8, len uintptr) uintptr {
	// Attention: Different value from Linux
	return 0x40000000 | ((len & 0x3fff) << 16) | (uintptr(group) << 8) | uintptr(num)
}

func _IOW(group, num uint8, len uintptr) uintptr {
	// Attention: Different value from Linux
	return 0x80000000 | ((len & 0x3fff) << 16) | (uintptr(group) << 8) | uintptr(num)
}

func _IOWR(group, num uint8, len uintptr) uintptr {
	return 0xc0000000 | ((len & 0x3fff) << 16) | (uintptr(group) << 8) | uintptr(num)
}
