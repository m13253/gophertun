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
)

func readCook(readRaw func() (*Packet, error), writeRaw func(*Packet) (bool, error), hwAddr net.HardwareAddr, buffer chan<- *Packet) (*Packet, error) {
retry:
	p, err := readRaw()
	if err != nil {
		return nil, err
	}
	if p == nil {
		goto retry
	}
	out, reply := proxyARP(p, hwAddr)
	for _, i := range reply {
		_, _ = writeRaw(i)
	}
	if len(out) == 0 {
		goto retry
	}
	for _, i := range out[1:] {
		select {
		case buffer <- i:
		default:
		}
	}
	return out[0], nil
}

func writeCook(writeRaw func(*Packet) (bool, error), p *Packet, mtuFunc func() (int, error), hwAddr net.HardwareAddr, buffer chan<- *Packet) error {
	out, reply := proxyARP(p, hwAddr)
	for _, i := range reply {
		select {
		case buffer <- i:
		default:
		}
	}
	var firstErr error
	mtu := 0
	for _, i := range out {
		needFrag, err := writeRaw(i)
		if !needFrag && err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if needFrag && mtuFunc != nil {
			if mtu <= 0 {
				mtu, err = mtuFunc()
				if err != nil {
					return err
				}
			}
			out1, reply1 := fragmentPacket(i, mtu)
			for _, j := range reply1 {
				select {
				case buffer <- j:
				default:
				}
			}
			for _, j := range out1 {
				_, err := writeRaw(j)
				if err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}
	}
	return firstErr
}
