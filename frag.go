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
	"fmt"
	"log"
)

func fragmentPacket(p *Packet, mtu int) (out []*Packet, reply []*Packet) {
	if mtu <= 0 {
		panic(fmt.Sprintf("gophertun: invalid MTU (%d)", mtu))
	}

	switch p.Format {

	case FormatIP:
		if len(p.Payload) <= mtu {
			return []*Packet{p}, nil
		}
		switch p.EtherType {
		case EtherTypeIPv4:
			packet := &CodecIPv4{}
			err := packet.Decode(p.Payload)
			if err != nil {
				log.Printf("Warning: %s\n", err)
				return nil, nil
			}
			if packet.Flags&0x2 != 0 {
				if icmp, ok := packet.Payload.(*CodecICMP); ok {
					if icmp.Type != 0 && icmp.Type != 8 {
						return nil, nil
					}
				}
				return nil, generateICMPPacketTooBig(p, packet)
			}
			return fragmentIPv4Packet(p, packet, mtu), nil

		case EtherTypeIPv6:
			packet := &CodecIPv6{}
			err := packet.Decode(p.Payload)
			if err != nil {
				log.Printf("Warning: %s\n", err)
				return nil, nil
			}
			for layer := packet.Payload; layer != nil; layer = layer.NextLayer() {
				if icmpv6, ok := layer.(*CodecICMPv6); ok {
					if icmpv6.Type < 128 {
						return truncateIPv6Packet(p, packet, mtu), nil
					}
				}
			}
			return nil, generateICMPv6PacketTooBig(p, packet, mtu)

		default:
			return nil, nil
		}

	case FormatEthernet:
		if len(p.Payload) <= mtu+EthernetHeaderSize {
			return []*Packet{p}, nil
		}
		frame := &CodecEthernet{}
		err := frame.Decode(p.Payload)
		if err != nil {
			log.Printf("Warning: %s\n", err)
			return nil, nil
		}

		switch frame.Payload.(type) {
		case *CodecIPv4:
			packet := frame.Payload.(*CodecIPv4)
			if packet.Flags&0x2 != 0 {
				if icmp, ok := packet.Payload.(*CodecICMP); ok {
					if icmp.Type != 0 && icmp.Type != 8 {
						return nil, nil
					}
				}
				return nil, generateICMPPacketTooBig(p, frame)
			}
			return fragmentIPv4Packet(p, packet, mtu), nil

		case *CodecIPv6:
			packet := frame.Payload.(*CodecIPv6)
			for layer := packet.Payload; layer != nil; layer = layer.NextLayer() {
				if icmpv6, ok := layer.(*CodecICMPv6); ok {
					if icmpv6.Type < 128 {
						return truncateIPv6Packet(p, packet, mtu), nil
					}
				}
			}
			return nil, generateICMPv6PacketTooBig(p, frame, mtu)

		default:
			return nil, nil
		}

	default:
		return []*Packet{p}, nil
	}
}

func generateICMPPacketTooBig(p *Packet, c Codec) (reply []*Packet) {
	switch p.Format {

	case FormatIP:
		originalHeader := p.Payload
		if len(originalHeader) > 28 {
			originalHeader = originalHeader[:28]
		}
		cIPv4 := c.(*CodecIPv4)
		reply := &CodecIPv4{
			Version:     4,
			TTL:         DefaultTTL,
			Protocol:    1,
			Source:      cIPv4.Source,
			Destination: cIPv4.Source,
			Payload: &CodecICMP{
				Type:    4,
				Code:    0,
				Payload: &CodecRaw{originalHeader, nil},
			},
		}
		replyPacket, err := reply.Encode()
		if err != nil {
			panic(err)
		}
		return []*Packet{
			&Packet{
				Format:    FormatIP,
				EtherType: EtherTypeIPv4,
				Payload:   replyPacket,
			},
		}

	case FormatEthernet:
		originalHeader := p.Payload[14:]
		if len(originalHeader) > 28 {
			originalHeader = originalHeader[:28]
		}
		cEthernet := c.(*CodecEthernet)
		cIPv4 := cEthernet.Payload.(*CodecIPv4)
		reply := &CodecEthernet{
			Destination: cEthernet.Source,
			Source:      cEthernet.Destination,
			Type:        EtherTypeIPv4,
			Payload: &CodecIPv4{
				Version:     4,
				TTL:         DefaultTTL,
				Protocol:    1,
				Source:      cIPv4.Source,
				Destination: cIPv4.Source,
				Payload: &CodecICMP{
					Type:    4,
					Code:    0,
					Payload: &CodecRaw{originalHeader, nil},
				},
			},
		}
		replyPacket, err := reply.Encode()
		if err != nil {
			panic(err)
		}
		return []*Packet{
			&Packet{
				Format:    FormatEthernet,
				EtherType: EtherTypeIPv4,
				Payload:   replyPacket,
			},
		}

	default:
		panic(ErrUnsupportedProtocol)
	}
}

func generateICMPv6PacketTooBig(p *Packet, c Codec, mtu int) (reply []*Packet) {
	switch p.Format {

	case FormatIP:
		originalHeader := p.Payload
		if len(originalHeader) > mtu-48 {
			originalHeader = originalHeader[:mtu-48]
		}
		if len(originalHeader) > 1232 {
			originalHeader = originalHeader[:1232]
		}
		cIPv6 := c.(*CodecIPv6)
		reply := &CodecIPv6{
			Version:     6,
			Flowlabel:   cIPv6.Flowlabel,
			NextHeader:  58,
			HopLimit:    DefaultTTL,
			Source:      cIPv6.Source,
			Destination: cIPv6.Source,
			Payload: &CodecICMPv6{
				Type:    2,
				Omni:    uint32(mtu),
				Payload: &CodecRaw{originalHeader, nil},
			},
		}
		replyPacket, err := reply.Encode()
		if err != nil {
			panic(err)
		}
		return []*Packet{
			&Packet{
				Format:    FormatIP,
				EtherType: EtherTypeIPv6,
				Payload:   replyPacket,
			},
		}

	case FormatEthernet:
		originalHeader := p.Payload[14:]
		if len(originalHeader) > mtu-48 {
			originalHeader = originalHeader[:mtu-48]
		}
		if len(originalHeader) > 1232 {
			originalHeader = originalHeader[:1232]
		}
		cEthernet := c.(*CodecEthernet)
		cIPv6 := cEthernet.Payload.(*CodecIPv6)
		reply := &CodecEthernet{
			Destination: cEthernet.Source,
			Source:      cEthernet.Destination,
			Type:        EtherTypeIPv4,
			Payload: &CodecIPv6{
				Version:     6,
				Flowlabel:   cIPv6.Flowlabel,
				NextHeader:  58,
				HopLimit:    DefaultTTL,
				Source:      cIPv6.Source,
				Destination: cIPv6.Source,
				Payload: &CodecICMPv6{
					Type:    2,
					Omni:    uint32(mtu),
					Payload: &CodecRaw{originalHeader, nil},
				},
			},
		}
		replyPacket, err := reply.Encode()
		if err != nil {
			panic(err)
		}
		return []*Packet{
			&Packet{
				Format:    FormatEthernet,
				EtherType: EtherTypeIPv6,
				Payload:   replyPacket,
			},
		}

	default:
		panic(ErrUnsupportedProtocol)
	}
}

func fragmentIPv4Packet(p *Packet, c Codec, mtu int) (out []*Packet) {
	switch p.Format {

	case FormatIP:
		cIPv4 := c.(*CodecIPv4)
		if mtu < int(cIPv4.HeaderLength)+8 {
			return nil
		}
		fragmentSize := (mtu - int(cIPv4.HeaderLength)) & -8
		payload, err := cIPv4.Payload.Encode()
		if err != nil {
			panic(err)
		}
		payloadOffset := int(cIPv4.FragmentOffset)
		payloadLength := int(cIPv4.FragmentOffset) + int(cIPv4.TotalLength) - int(cIPv4.HeaderLength)
		out = make([]*Packet, 0, (payloadLength-payloadOffset)/fragmentSize+1)
		for offset := payloadOffset; offset < payloadLength; offset += fragmentSize {
			flags := cIPv4.Flags
			segmentPayload := payload[offset-payloadOffset:]
			log.Println(offset, fragmentSize, payloadLength)
			if offset+fragmentSize < payloadLength {
				flags |= 0x1
				segmentPayload = segmentPayload[:fragmentSize]
			}
			segment := &CodecIPv4{
				Version:        4,
				DSCP:           cIPv4.DSCP,
				ECN:            cIPv4.ECN,
				Identification: cIPv4.Identification,
				Flags:          flags,
				FragmentOffset: uint16(offset),
				TTL:            cIPv4.TTL,
				Protocol:       cIPv4.Protocol,
				Source:         cIPv4.Source,
				Destination:    cIPv4.Destination,
				Extra1:         cIPv4.Extra1,
				Payload:        &CodecRaw{segmentPayload, nil},
			}
			segmentPacket, err := segment.Encode()
			if err != nil {
				panic(err)
			}
			out = append(out, &Packet{
				Format:    FormatIP,
				EtherType: EtherTypeIPv4,
				Payload:   segmentPacket,
			})
		}
		return out

	case FormatEthernet:
		cEthernet := c.(*CodecEthernet)
		cIPv4 := cEthernet.Payload.(*CodecIPv4)
		if mtu < int(cIPv4.HeaderLength)+8 {
			return nil
		}
		fragmentSize := (mtu - int(cIPv4.HeaderLength)) & -8
		payloadOffset := int(cIPv4.FragmentOffset)
		payloadLength := int(cIPv4.FragmentOffset) + int(cIPv4.TotalLength) - int(cIPv4.HeaderLength)
		out = make([]*Packet, 0, (payloadLength-payloadOffset)/fragmentSize+1)
		for offset := payloadOffset; offset < payloadLength; offset += fragmentSize {
			flags := cIPv4.Flags
			if offset+fragmentSize < payloadLength {
				flags |= 0x1
			}
			segment := &CodecEthernet{
				Destination: cEthernet.Destination,
				Source:      cEthernet.Source,
				Type:        EtherTypeIPv4,
				Payload: &CodecIPv4{
					Version:        4,
					DSCP:           cIPv4.DSCP,
					ECN:            cIPv4.ECN,
					Identification: cIPv4.Identification,
					Flags:          flags,
					FragmentOffset: uint16(offset),
					TTL:            cIPv4.TTL,
					Protocol:       cIPv4.Protocol,
					Source:         cIPv4.Source,
					Destination:    cIPv4.Destination,
					Extra1:         cIPv4.Extra1,
				},
			}
			segmentPacket, err := segment.Encode()
			if err != nil {
				panic(err)
			}
			out = append(out, &Packet{
				Format:    FormatEthernet,
				EtherType: EtherTypeIPv4,
				Payload:   segmentPacket,
			})
		}
		return out

	default:
		panic(ErrUnsupportedProtocol)
	}
}

func truncateIPv6Packet(p *Packet, c Codec, mtu int) (out []*Packet) {
	switch p.Format {

	case FormatIP:
		return []*Packet{&Packet{
			Format:    FormatIP,
			EtherType: EtherTypeIPv6,
			Payload:   p.Payload[:mtu],
		}}

	case FormatEthernet:
		return []*Packet{&Packet{
			Format:    FormatEthernet,
			EtherType: EtherTypeIPv6,
			Payload:   p.Payload[:mtu+EthernetHeaderSize],
		}}

	default:
		panic(ErrUnsupportedProtocol)
	}
}
