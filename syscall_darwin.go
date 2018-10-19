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
)

const (
	_PF_SYSTEM        = syscall.AF_SYSTEM
	_SYSPROTO_CONTROL = 2
	_AF_SYS_CONTROL   = 2
	_UTUN_OPT_IFNAME  = 2
	_IF_NAMESIZE      = 16
)

type (
	ctl_info struct {
		ctl_id   uint32
		ctl_name [96]byte
	}
	ifreq_mtu struct {
		ifr_name [_IF_NAMESIZE]byte
		ifru_mtu int32
		_        [28 - _IF_NAMESIZE]byte
	}
)

var (
	_CTLIOCGINFO = _IOWR('N', 3, unsafe.Sizeof(ctl_info{}))
	_SIOCGIFMTU  = _IOWR('i', 51, unsafe.Sizeof(ifreq_mtu{}))
	_SIOCSIFMTU  = _IOW('i', 52, unsafe.Sizeof(ifreq_mtu{}))
)

type sockaddr_ctl struct {
	sc_len      uint8
	sc_family   uint8
	ss_sysaddr  uint16
	sc_id       uint32
	sc_unit     uint32
	sc_reserved [5]uint32
}
