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
)

func fragmentPacket(p *Packet, mtu int) (out []*Packet, reply []*Packet) {
	switch p.Format {

	case FormatIP:
		if len(p.Payload) <= mtu {
			return []*Packet{p}, nil
		}
		if p.EtherType != EtherTypeIPv4 {
			return nil, generatePacketTooBig(p, mtu)
		}

	case FormatEthernet:
		if len(p.Payload) <= mtu+EthernetHeaderSize {
			return []*Packet{p}, nil
		}
		ethertype := EtherType(binary.BigEndian.Uint16(p.Payload[12:14]))
		if ethertype != EtherTypeIPv4 {
			return nil, generatePacketTooBig(p, mtu)
		}

	default:
		return []*Packet{p}, nil
	}
	return nil, nil
}

func generatePacketTooBig(p *Packet, mtu int) []*Packet {
	switch p.Format {

	case FormatIP:

		switch p.EtherType {

		case EtherTypeIPv4:
			if len(p.Payload) < 20 {
				return nil
			}
			// Do not generate ICMP error for types other than PING
			if len(p.Payload) >= 21 && p.Payload[9] == 0x01 && p.Payload[20] != 0x08 {
				return nil
			}
			var buf []byte
			if len(p.Payload) < 28 {
				buf = make([]byte, 28+len(p.Payload))
			} else {
				buf = make([]byte, 56)
			}
			copy(buf[:2], []byte{0x45, 0x00})
			binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
			copy(buf[4:6], p.Payload[4:6])
			copy(buf[6:10], []byte{0x00, 0x00, DefaultTTL, 0x01})
			copy(buf[12:16], p.Payload[16:20])
			copy(buf[16:20], p.Payload[12:16])
			copy(buf[20:22], []byte{0x04, 0x00})
			copy(buf[28:], p.Payload)
			return []*Packet{
				&Packet{
					Format:    FormatIP,
					EtherType: EtherTypeIPv4,
					Payload:   buf,
				},
			}
		case EtherTypeIPv6:
			// TODO

		default:
			return nil

		}

	case FormatEthernet:

		if len(p.Payload) < EthernetHeaderSize {
			return nil
		}

		switch EtherType(binary.BigEndian.Uint16(p.Payload[12:14])) {

		case EtherTypeIPv4:

		case EtherTypeIPv6:

		default:
			return nil

		}

	}
	return nil
}
