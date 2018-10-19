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
	"golang.org/x/sys/unix"
)

const (
	_IFF_TUN         = 0x0001
	_IFF_TAP         = 0x0002
	_IFF_MULTI_QUEUE = 0x0100
)

type (
	ifreq_flags struct {
		ifr_name  [unix.IFNAMSIZ]byte
		ifr_flags int16
		_         int16
		_         [20]byte
	}
	ifreq_index struct {
		ifr_name    [unix.IFNAMSIZ]byte
		ifr_ifindex int32
		_           [20]byte
	}
	ifreq_mtu struct {
		ifr_name [unix.IFNAMSIZ]byte
		ifr_mtu  int32
		_        [20]byte
	}
)

var (
	_TUNSETIFF = _IOW('T', 202, 4)
)
