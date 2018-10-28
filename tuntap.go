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

import "net"

type TunTapConfig struct {
	NameHint              string
	AllowNameSuffix       bool
	PreferredNativeFormat PayloadFormat
	ExtraFlags            uint32
}

func (t *TunTapImpl) Read() (*Packet, error) {
	select {
	case p := <-t.buffer:
		return p, nil
	default:
		hwAddr := net.HardwareAddr(nil)
		if t.OutputFormat() != t.NativeFormat() {
			hwAddr = t.hwAddr
		}
		return readCook(t.readRaw, t.writeRaw, hwAddr, t.buffer)
	}
}

func (t *TunTapImpl) Write(packet *Packet, pmtud bool) error {
	mtuFunc := (func() (int, error))(nil)
	if pmtud {
		mtuFunc = t.MTU
	}
	hwAddr := net.HardwareAddr(nil)
	if t.OutputFormat() != t.NativeFormat() {
		hwAddr = t.hwAddr
	}
	return writeCook(t.writeRaw, packet, mtuFunc, hwAddr, t.buffer)
}
