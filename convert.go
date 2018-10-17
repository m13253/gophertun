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
	"encoding/binary"
	"errors"
	"net"
)

func (p *Packet) ConvertTo(outputFormat PayloadFormat, hwAddr net.HardwareAddr) (*Packet, error) {
	if p == nil {
		return nil, nil
	}
	switch outputFormat {
	case FormatIP:
		switch p.Format {
		case FormatIP:
			return p, nil
		case FormatEthernet:
			if len(p.Payload) < 14 {
				return nil, errors.New("gophertun: invalid Ethernet frame")
			}
			return &Packet{
				Format:  FormatIP,
				Proto:   EtherType(binary.BigEndian.Uint16(p.Payload[12:14])),
				Payload: p.Payload[14:],
				Extra:   p.Extra,
			}, nil
		}
	case FormatEthernet:
		switch p.Format {
		case FormatIP:
			frame := make([]byte, len(p.Payload)+14)
			copy(frame[:6], hwAddr)
			copy(frame[6:12], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
			binary.BigEndian.PutUint16(frame[12:14], uint16(p.Proto))
			copy(frame[14:], p.Payload)
			return &Packet{
				Format:  FormatEthernet,
				Proto:   EtherTypeLoop,
				Payload: frame,
				Extra:   p.Extra,
			}, nil
		case FormatEthernet:
			return p, nil
		}
	}
	return nil, UnsupportedProtocolError
}
