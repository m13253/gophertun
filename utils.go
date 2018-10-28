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
	"net"
	"os"
	"runtime"
	"syscall"
)

func dupBytes(bytes []byte) []byte {
	if len(bytes) == 0 {
		return nil
	}
	result := make([]byte, len(bytes))
	copy(result, bytes)
	return result
}

func checksum(buf []byte) uint16 {
	if len(buf) > 0xffff {
		panic("gophertun: checksum length > 65535 unimplemented yet")
	}
	sum := uint32(0)
	i := 0
	for ; i < len(buf)-1; i += 2 {
		sum += uint32(buf[i]) << 8
		sum += uint32(buf[i+1])
	}
	if i < len(buf) {
		sum += uint32(buf[len(buf)-1])
	}
	return ^uint16(sum>>16 + sum)
}

func simplifyIPNet(ipnet net.IPNet) *net.IPNet {
	if ipv4net := ipnetTo4(ipnet); ipv4net != nil {
		return ipv4net
	}
	if ipv6net := ipnetTo16(ipnet); ipv6net != nil {
		return ipv6net
	}
	return nil
}

func ipnetTo4(ipnet net.IPNet) *net.IPNet {
	if ipv4 := ipnet.IP.To4(); ipv4 != nil {
		ones, bits := ipnet.Mask.Size()
		if bits < 32 {
			return nil
		}
		if ones == 0 {
			return &net.IPNet{
				IP:   ipv4,
				Mask: net.CIDRMask(0, 32),
			}
		}
		if bits-ones > 32 {
			return nil
		}
		return &net.IPNet{
			IP:   ipv4,
			Mask: net.CIDRMask(ones+32-bits, 32),
		}
	}
	return nil
}

func ipnetTo16(ipnet net.IPNet) *net.IPNet {
	if ip := ipnet.IP.To16(); ip != nil {
		ones, bits := ipnet.Mask.Size()
		if bits < 32 {
			return nil
		}
		if ones == 0 {
			return &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(0, 128),
			}
		}
		if bits-ones > 128 {
			return nil
		}
		return &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(ones+128-bits, 128),
		}
	}
	return nil
}

func isErrorEMSGSIZE(err error) bool {
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	errSyscallError, ok := errOpError.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	errErrno, ok := errSyscallError.Err.(syscall.Errno)
	if !ok {
		return false
	}
	if errErrno == syscall.EMSGSIZE {
		return true
	}
	const WSAEMSGSIZE = 10040
	if runtime.GOOS == "windows" && errErrno == WSAEMSGSIZE {
		return true
	}
	return false
}
