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
	"fmt"
	"net"
)

type Codec interface {
	Decode(buf []byte) error
	Encode() ([]byte, error)
	NextLayer() Codec
}

type hasPseudoHeader interface {
	Codec
	encodePseudoHeader() ([]byte, error)
}

type wantPseudoHeader interface {
	Codec
	setPseudoHeader(pseudoHeader hasPseudoHeader)
}

type CodecRaw struct {
	Payload []byte
	Err     error
}

type CodecEthernet struct {
	Destination net.HardwareAddr
	Source      net.HardwareAddr
	Type        EtherType
	Payload     Codec
}

type CodecARP struct {
	HardwareType       uint16
	ProtocolType       EtherType
	HardwareSize       uint8
	ProtocolSize       uint8
	Opcode             uint16
	SenderHardwareAddr net.HardwareAddr
	SenderProtocolAddr net.IP
	TargetHardwareAddr net.HardwareAddr
	TargetProtocolAddr net.IP
	Extra              []byte
}

type CodecIPv4 struct {
	Version        uint8
	HeaderLength   uint8 // raw * 4
	DSCP           uint8
	ECN            uint8
	TotalLength    uint16
	Identification uint16
	Flags          uint8
	FragmentOffset uint16 // raw * 8
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	Source         net.IP
	Destination    net.IP
	Extra1         []byte
	Payload        Codec
	Extra2         []byte
}

type CodecIPv6 struct {
	Version       uint8
	DSCP          uint8
	ECN           uint8
	Flowlabel     uint32
	PayloadLength uint16
	NextHeader    uint8
	HopLimit      uint8
	Source        net.IP
	Destination   net.IP
	Payload       Codec
	Extra         []byte
}

type CodecIPv6HopByHop struct {
	NextHeader   uint8
	HeaderLength uint16 // raw * 8 + 8
	FirstOption  *CodecIPv6HopByHopOption
	Payload      Codec
	pseudoHeader hasPseudoHeader
}

type CodecIPv6HopByHopOption struct {
	Type       uint8
	DataLength uint8
	Data       Codec
	NextOption *CodecIPv6HopByHopOption
}

type CodecIPv6Fragment struct {
	NextHeader     uint8
	Reserved1      uint8
	FragmentOffset uint16 // raw * 8
	Reserved2      uint8
	MoreFragment   bool
	Identification uint32
	Payload        Codec
	pseudoHeader   hasPseudoHeader
}

type CodecICMP struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Reserved uint32
	Payload  Codec
}

type CodecICMPv6 struct {
	Type         uint8
	Code         uint8
	Checksum     uint16
	Omni         uint32
	Payload      Codec
	pseudoHeader hasPseudoHeader
}

func (c *CodecRaw) Decode(buf []byte) error {
	c.Payload = buf
	c.Err = nil
	return nil
}

func (c *CodecRaw) Encode() ([]byte, error) {
	return c.Payload, nil
}

func (c *CodecRaw) NextLayer() Codec {
	return nil
}

func (c *CodecRaw) String() string {
	return fmt.Sprintf("&CodecRaw{0x%x, %v}", c.Payload, c.Err)
}

func (c *CodecEthernet) Decode(buf []byte) error {
	if len(buf) < EthernetHeaderSize {
		return errors.New("gophertun: invalid Ethernet frame")
	}
	c.Destination = dupBytes(buf[:6])
	c.Source = dupBytes(buf[6:12])
	c.Type = EtherType(binary.BigEndian.Uint16(buf[12:14]))
	switch c.Type {
	case EtherTypeARP:
		c.Payload = &CodecARP{}
	case EtherTypeIPv4:
		c.Payload = &CodecIPv4{}
	case EtherTypeIPv6:
		c.Payload = &CodecIPv6{}
	default:
		c.Payload = &CodecRaw{}
	}
	err := c.Payload.Decode(buf[EthernetHeaderSize:])
	if err != nil {
		c.Payload = &CodecRaw{buf[EthernetHeaderSize:], err}
	}
	return nil
}

func (c *CodecEthernet) Encode() ([]byte, error) {
	payload, err := c.Payload.Encode()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, len(payload)+EthernetHeaderSize)
	copy(buf[:6], c.Destination)
	copy(buf[6:12], c.Source)
	binary.BigEndian.PutUint16(buf[12:14], uint16(c.Type))
	copy(buf[EthernetHeaderSize:], payload)
	return buf, nil
}

func (c *CodecEthernet) NextLayer() Codec {
	return c.Payload
}

func (c *CodecEthernet) String() string {
	return fmt.Sprintf("&CodecEthernet{%s-→%s, Type:0x%04x, %v}", c.Source, c.Destination, c.Type, c.Payload)
}

func (c *CodecARP) Decode(buf []byte) error {
	if len(buf) < 8 {
		return errors.New("gophertun: invalid ARP packet")
	}
	c.HardwareType = binary.BigEndian.Uint16(buf[:2])
	c.ProtocolType = EtherType(binary.BigEndian.Uint16(buf[2:4]))
	c.HardwareSize = buf[4]
	c.ProtocolSize = buf[5]
	c.Opcode = binary.BigEndian.Uint16(buf[6:8])
	if len(buf) < 8+(int(c.HardwareSize)+int(c.ProtocolSize))*2 {
		return errors.New("gophertun: invalid ARP packet")
	}
	c.SenderHardwareAddr = dupBytes(buf[8 : 8+int(c.HardwareSize)])
	c.SenderProtocolAddr = dupBytes(buf[8+int(c.HardwareSize) : 8+int(c.HardwareSize)+int(c.ProtocolSize)])
	c.TargetHardwareAddr = dupBytes(buf[8+int(c.HardwareSize)+int(c.ProtocolSize) : 8+int(c.HardwareSize)*2+int(c.ProtocolSize)])
	c.TargetProtocolAddr = dupBytes(buf[8+int(c.HardwareSize)*2+int(c.ProtocolSize) : 8+(int(c.HardwareSize)+int(c.ProtocolSize))*2])
	if len(buf) > 8+(int(c.HardwareSize)+int(c.ProtocolSize))*2 {
		c.Extra = buf[8+(int(c.HardwareSize)+int(c.ProtocolSize))*2:]
	} else {
		c.Extra = nil
	}
	return nil
}

func (c *CodecARP) Encode() ([]byte, error) {
	buf := make([]byte, 8+(int(c.HardwareSize)+int(c.ProtocolSize))*2+len(c.Extra))
	binary.BigEndian.PutUint16(buf[:2], c.HardwareType)
	binary.BigEndian.PutUint16(buf[2:4], uint16(c.ProtocolType))
	buf[4] = c.HardwareSize
	buf[5] = c.ProtocolSize
	binary.BigEndian.PutUint16(buf[6:8], c.Opcode)
	copy(buf[8:8+int(c.HardwareSize)], c.SenderHardwareAddr)
	copy(buf[8+int(c.HardwareSize):8+int(c.HardwareSize)+int(c.ProtocolSize)], c.SenderProtocolAddr)
	copy(buf[8+int(c.HardwareSize)+int(c.ProtocolSize):8+int(c.HardwareSize)*2+int(c.ProtocolSize)], c.TargetHardwareAddr)
	copy(buf[8+int(c.HardwareSize)*2+int(c.ProtocolSize):8+(int(c.HardwareSize)+int(c.ProtocolSize))*2], c.TargetProtocolAddr)
	copy(buf[8+(int(c.HardwareSize)+int(c.ProtocolSize))*2:], c.Extra)
	return buf, nil
}

func (c *CodecARP) NextLayer() Codec {
	return nil
}

func (c *CodecARP) String() string {
	return fmt.Sprintf("&CodecARP{HT:0x%04x, PT:0x%04x, HS:%d, PS:%d, Op:0x%x, %s (%s)-→%s (%s)}", c.HardwareType, c.ProtocolType, c.HardwareSize, c.ProtocolSize, c.Opcode, c.SenderHardwareAddr, c.SenderProtocolAddr, c.TargetHardwareAddr, c.TargetProtocolAddr)
}

func (c *CodecIPv4) Decode(buf []byte) error {
	if len(buf) < 20 {
		return errors.New("gophertun: invalid IPv4 packet")
	}

	c.Version = buf[0] >> 4
	c.HeaderLength = (buf[0] & 0x0f) * 4
	if c.HeaderLength < 20 || len(buf) < int(c.HeaderLength) {
		return errors.New("gophertun: invalid IPv4 packet")
	}
	c.DSCP = buf[1] >> 2
	c.ECN = buf[1] & 0x3
	c.TotalLength = binary.BigEndian.Uint16(buf[2:4])
	if c.TotalLength < uint16(c.HeaderLength) {
		return errors.New("gophertun: invalid IPv4 packet")
	}
	c.Identification = binary.BigEndian.Uint16(buf[4:6])
	c.Flags = buf[6] >> 5
	c.FragmentOffset = (binary.BigEndian.Uint16(buf[6:8]) & 0x1fff) * 8
	c.TTL = buf[8]
	c.Protocol = buf[9]
	c.HeaderChecksum = binary.BigEndian.Uint16(buf[10:12])
	if c.HeaderChecksum != 0 && checksum(buf[:c.HeaderLength]) != 0 {
		return errors.New("gophertun: IPv4 checksum error")
	}
	c.Source = dupBytes(buf[12:16])
	c.Destination = dupBytes(buf[16:20])

	if c.HeaderLength > 20 {
		c.Extra1 = buf[20:c.HeaderLength]
	} else {
		c.Extra1 = nil
	}

	if len(buf) < int(c.TotalLength) {
		c.Payload = &CodecRaw{buf[c.HeaderLength:], errors.New("gophertun: incomplete IPv4 payload")}
	} else {
		if c.Flags&0x1 == 0x0 && c.FragmentOffset == 0 {
			switch c.Protocol {
			case 1:
				c.Payload = &CodecICMP{}
			default:
				c.Payload = &CodecRaw{}
			}
		} else {
			c.Payload = &CodecRaw{}
		}
		if wph, ok := c.Payload.(wantPseudoHeader); ok {
			wph.setPseudoHeader(c)
		}
		err := c.Payload.Decode(buf[c.HeaderLength:c.TotalLength])
		if err != nil {
			c.Payload = &CodecRaw{buf[c.HeaderLength:c.TotalLength], err}
		}
	}

	if len(buf) > int(c.TotalLength) {
		c.Extra2 = buf[c.TotalLength:]
	} else {
		c.Extra2 = nil
	}

	return nil
}

func (c *CodecIPv4) Encode() ([]byte, error) {
	if c.FragmentOffset%8 != 0 {
		return nil, errors.New("gophertun: invalid IPv4 packet")
	}
	c.Version = 4
	headerLength := 20 + ((len(c.Extra1) - 1) | 3) + 1
	if headerLength > 60 {
		return nil, errors.New("gophertun: invalid IPv4 packet")
	}
	c.HeaderLength = uint8(headerLength)

	payload, err := c.Payload.Encode()
	if err != nil {
		return nil, err
	}
	totalLength := int(c.HeaderLength) + len(payload)
	if totalLength > 0xffff {
		return nil, errors.New("gophertun: invalid IPv4 packet")
	}
	c.TotalLength = uint16(totalLength)

	buf := make([]byte, int(c.HeaderLength)+len(payload)+len(c.Extra2))
	buf[0] = (c.Version << 4) | ((c.HeaderLength / 4) & 0x0f)
	buf[1] = (c.DSCP << 2) | (c.ECN & 0x3)
	binary.BigEndian.PutUint16(buf[2:4], c.TotalLength)
	binary.BigEndian.PutUint16(buf[4:6], c.Identification)
	buf[6] = (c.Flags << 5) | uint8(c.FragmentOffset/2048)
	buf[7] = uint8(c.FragmentOffset / 8)
	buf[8] = c.TTL
	buf[9] = c.Protocol
	copy(buf[12:16], c.Source.To4())
	copy(buf[16:20], c.Destination.To4())
	copy(buf[20:c.HeaderLength], c.Extra1)
	copy(buf[c.HeaderLength:c.TotalLength], payload)
	copy(buf[c.TotalLength:], c.Extra2)

	c.HeaderChecksum = checksum(buf[:c.HeaderLength])
	binary.BigEndian.PutUint16(buf[10:12], c.HeaderChecksum)

	return buf, nil
}

func (c *CodecIPv4) encodePseudoHeader() ([]byte, error) {
	buf := make([]byte, 12)
	copy(buf[:4], c.Source.To4())
	copy(buf[4:8], c.Destination.To4())
	buf[9] = c.Protocol
	return buf, nil
}

func (c *CodecIPv4) NextLayer() Codec {
	return c.Payload
}

func (c *CodecIPv4) String() string {
	return fmt.Sprintf("&CodecIPv4{V:%d, HL:%d, DSCP:0x%02x, ECN:%d, Len:%d, ID:0x%04x, Flag:0x%x, FO:%d, TTL:%d, Proto:%d, Csum:0x%04x, %s-→%s, %v}", c.Version, c.HeaderLength, c.DSCP, c.ECN, c.TotalLength, c.Identification, c.Flags, c.FragmentOffset, c.TTL, c.Protocol, c.HeaderChecksum, c.Source, c.Destination, c.Payload)
}

func (c *CodecIPv6) Decode(buf []byte) error {
	if len(buf) < 40 {
		return errors.New("gophertun: invalid IPv6 packet")
	}
	c.Version = buf[0] >> 4
	c.DSCP = ((buf[0] & 0x0f) << 2) | (buf[1] >> 6)
	c.ECN = (buf[1] & 0x30) >> 4
	c.Flowlabel = binary.BigEndian.Uint32(buf[:4]) & 0x000fffff
	c.PayloadLength = binary.BigEndian.Uint16(buf[4:6])
	c.NextHeader = buf[6]
	c.HopLimit = buf[7]
	c.Source = dupBytes(buf[8:24])
	c.Destination = dupBytes(buf[24:40])

	if len(buf) < 40+int(c.PayloadLength) {
		c.Payload = &CodecRaw{buf[40:], errors.New("gophertun: incomplete IPv6 payload")}
	} else {
		switch c.NextHeader {
		case 0:
			c.Payload = &CodecIPv6HopByHop{}
		case 44:
			c.Payload = &CodecIPv6Fragment{}
		case 58:
			c.Payload = &CodecICMPv6{}
		default:
			c.Payload = &CodecRaw{}
		}
		if wph, ok := c.Payload.(wantPseudoHeader); ok {
			wph.setPseudoHeader(c)
		}
		err := c.Payload.Decode(buf[40 : 40+int(c.PayloadLength)])
		if err != nil {
			c.Payload = &CodecRaw{buf[40 : 40+int(c.PayloadLength)], err}
		}
	}

	if len(buf) > 40+int(c.PayloadLength) {
		c.Extra = buf[40+int(c.PayloadLength):]
	} else {
		c.Extra = nil
	}

	return nil
}

func (c *CodecIPv6) Encode() ([]byte, error) {
	c.Version = 6

	payload, err := c.Payload.Encode()
	if err != nil {
		return nil, err
	}
	payloadLength := len(payload)
	if payloadLength > 0xffff {
		return nil, errors.New("gophertun: invalid IPv6 packet")
	}
	c.PayloadLength = uint16(payloadLength)

	buf := make([]byte, 40+len(payload)+len(c.Extra))
	buf[0] = (c.Version << 4) | ((c.DSCP & 0x3c) >> 2)
	buf[1] = (c.DSCP << 6) | ((c.ECN & 0x3) << 4) | uint8((c.Flowlabel&0xf0000)>>16)
	binary.BigEndian.PutUint16(buf[2:4], uint16(c.Flowlabel))
	binary.BigEndian.PutUint16(buf[4:6], c.PayloadLength)
	buf[6] = c.NextHeader
	buf[7] = c.HopLimit
	copy(buf[8:24], c.Source.To16())
	copy(buf[24:40], c.Destination.To16())
	copy(buf[40:40+int(c.PayloadLength)], payload)
	copy(buf[40+int(c.PayloadLength):], c.Extra)

	return buf, nil
}

func (c *CodecIPv6) encodePseudoHeader() ([]byte, error) {
	buf := make([]byte, 40)
	copy(buf[:16], c.Source.To16())
	copy(buf[16:32], c.Destination.To16())
	buf[39] = c.NextHeader
	return buf, nil
}

func (c *CodecIPv6) NextLayer() Codec {
	return c.Payload
}

func (c *CodecIPv6) String() string {
	return fmt.Sprintf("&CodecIPv6{V:%d, DSCP:0x%02x, ECN:%d, Flow:0x%05x, Len:%d, NH:%d, HL:%d, %s-→%s, %v}", c.Version, c.DSCP, c.ECN, c.Flowlabel, c.PayloadLength, c.NextHeader, c.HopLimit, c.Source, c.Destination, c.Payload)
}

func (c *CodecIPv6HopByHop) Decode(buf []byte) error {
	if len(buf) < 8 {
		return errors.New("gophertun: invalid IPv6-Hop-by-Hop header")
	}
	c.NextHeader = buf[0]
	c.HeaderLength = uint16(buf[1])*8 + 8
	if len(buf) < int(c.HeaderLength) {
		return errors.New("gophertun: invalid IPv6-Hop-by-Hop header")
	}
	c.FirstOption = &CodecIPv6HopByHopOption{}
	c.FirstOption.Decode(buf[2:c.HeaderLength])

	switch c.NextHeader {
	case 0:
		c.Payload = &CodecIPv6HopByHop{}
	case 44:
		c.Payload = &CodecIPv6Fragment{}
	case 58:
		c.Payload = &CodecICMPv6{}
	default:
		c.Payload = &CodecRaw{}
	}
	if wph, ok := c.Payload.(wantPseudoHeader); ok {
		wph.setPseudoHeader(c.pseudoHeader)
	}
	err := c.Payload.Decode(buf[c.HeaderLength:])
	if err != nil {
		c.Payload = &CodecRaw{buf[c.HeaderLength:], err}
	}

	return nil
}

func (c *CodecIPv6HopByHop) Encode() ([]byte, error) {
	options, err := c.FirstOption.Encode()
	if err != nil {
		return nil, err
	}
	headerLength := ((2 + len(options) - 1) | 7) + 1
	if headerLength > 0x800 {
		return nil, errors.New("gophertun: invalid IPv6-Hop-by-Hop header")
	}
	c.HeaderLength = uint16(headerLength)

	payload, err := c.Payload.Encode()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, int(c.HeaderLength)+len(payload))
	buf[0] = c.NextHeader
	buf[1] = uint8(c.HeaderLength/8 - 1)
	copy(buf[2:c.HeaderLength], options)
	copy(buf[c.HeaderLength:], payload)

	return buf, nil
}

func (c *CodecIPv6HopByHop) setPseudoHeader(pseudoHeader hasPseudoHeader) {
	c.pseudoHeader = pseudoHeader
}

func (c *CodecIPv6HopByHop) NextLayer() Codec {
	return c.Payload
}

func (c *CodecIPv6HopByHop) String() string {
	return fmt.Sprintf("&CodecIPv6HopByHop{NH:%d, Len:%d, Options:{%v}, %v}", c.NextHeader, c.HeaderLength, c.FirstOption, c.Payload)
}

func (c *CodecIPv6HopByHopOption) Decode(buf []byte) error {
retry:
	if len(buf) == 0 {
		c.Type = 0
		c.DataLength = 0
		c.Data = &CodecRaw{nil, nil}
		c.NextOption = nil
		return nil
	}
	if buf[0] == 0 {
		buf = buf[1:]
		goto retry
	}
	if len(buf) < 2 {
		return errors.New("gophertun: invalid IPv6-Hop-by-Hop option")
	}
	c.Type = buf[0]
	if c.Type&0xc0 != 0x00 {
		// Discard the packet and take action [RFC 2460, Section 4.2]
		// Since we can not take any further action, we will report an error to abort the parser.
		return errors.New("gophertun: unsupported IPv6-Hop-by-Hop option")
	}
	c.DataLength = buf[1]
	if len(buf) < 2+int(c.DataLength) {
		return errors.New("gophertun: invalid IPv6-Hop-by-Hop option")
	}
	c.Data = &CodecRaw{buf[2 : 2+int(c.DataLength)], nil}
	if len(buf) > 2+int(c.DataLength) {
		c.NextOption = &CodecIPv6HopByHopOption{}
		return c.NextOption.Decode(buf[2+int(c.DataLength):])
	}
	c.NextOption = nil
	return nil
}

func (c *CodecIPv6HopByHopOption) Encode() ([]byte, error) {
	if c.Type == 0 {
		return nil, nil
	}
	data, err := c.Data.Encode()
	if err != nil {
		return nil, err
	}
	dataLength := len(data)
	if dataLength > 0xff {
		return nil, errors.New("gophertun: invalid IPv6-Hop-by-Hop option")
	}
	c.DataLength = uint8(dataLength)
	buf := make([]byte, 2+dataLength)
	buf[0] = c.Type
	buf[1] = c.DataLength
	copy(buf[2:], data)
	return buf, nil
}

func (c *CodecIPv6HopByHopOption) NextLayer() Codec {
	return c.NextOption
}

func (c *CodecIPv6HopByHopOption) String() string {
	if c.NextOption == nil {
		return fmt.Sprintf("{Type:%d, Len:%d, %v}", c.Type, c.DataLength, c.Data)
	}
	return fmt.Sprintf("{Type:%d, Len:%d, %v}, %v", c.Type, c.DataLength, c.Data, c.NextOption)
}
func (c *CodecIPv6Fragment) Decode(buf []byte) error {
	if len(buf) < 8 {
		return errors.New("gophertun: invalid IPv6-Fragment header")
	}
	c.NextHeader = buf[0]
	c.Reserved1 = buf[1]
	c.FragmentOffset = binary.BigEndian.Uint16(buf[2:4]) & 0xfff8
	c.Reserved2 = (buf[3] & 0x6) >> 1
	c.MoreFragment = (buf[3] & 0x1) != 0
	c.Identification = binary.BigEndian.Uint32(buf[4:8])

	switch c.NextHeader {
	case 0:
		c.Payload = &CodecIPv6HopByHop{}
	case 44:
		c.Payload = &CodecIPv6Fragment{}
	case 58:
		c.Payload = &CodecICMPv6{}
	default:
		c.Payload = &CodecRaw{}
	}
	if wph, ok := c.Payload.(wantPseudoHeader); ok {
		wph.setPseudoHeader(c.pseudoHeader)
	}
	err := c.Payload.Decode(buf[8:])
	if err != nil {
		c.Payload = &CodecRaw{buf[8:], err}
	}

	return nil
}

func (c *CodecIPv6Fragment) Encode() ([]byte, error) {
	if c.FragmentOffset&0x7 != 0 {
		return nil, errors.New("gophertun: invalid IPv6-Fragment header")
	}

	payload, err := c.Payload.Encode()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 8+len(payload))
	buf[0] = c.NextHeader
	buf[1] = c.Reserved1
	buf[2] = uint8(c.FragmentOffset >> 8)
	buf[3] = uint8(c.FragmentOffset&0xf8) | ((c.Reserved2 & 0x3) << 1)
	if c.MoreFragment {
		buf[3] |= 0x1
	}
	binary.BigEndian.PutUint32(buf[4:8], c.Identification)
	copy(buf[8:], payload)

	return buf, nil
}

func (c *CodecIPv6Fragment) setPseudoHeader(pseudoHeader hasPseudoHeader) {
	c.pseudoHeader = pseudoHeader
}

func (c *CodecIPv6Fragment) NextLayer() Codec {
	return c.Payload
}

func (c *CodecIPv6Fragment) String() string {
	return fmt.Sprintf("&CodecIPv6Fragment{NH:%d, FO:%d, M:%v, %v}", c.NextHeader, c.FragmentOffset, c.MoreFragment, c.Payload)
}

func (c *CodecICMP) Decode(buf []byte) error {
	if len(buf) < 8 {
		return errors.New("gophertun: invalid ICMP packet")
	}
	c.Type = buf[0]
	c.Code = buf[1]
	c.Checksum = binary.BigEndian.Uint16(buf[2:4])
	if c.Checksum != 0 && checksum(buf[:8]) != 0 {
		return errors.New("gophertun: ICMP checksum error")
	}
	c.Reserved = binary.BigEndian.Uint32(buf[4:8])
	c.Payload = &CodecRaw{buf[8:], nil}
	return nil
}

func (c *CodecICMP) Encode() ([]byte, error) {
	payload, err := c.Payload.Encode()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 8+len(payload))
	buf[0] = c.Type
	buf[1] = c.Code
	binary.BigEndian.PutUint32(buf[4:8], c.Reserved)
	copy(buf[8:], payload)

	c.Checksum = checksum(buf)
	binary.BigEndian.PutUint16(buf[:4], c.Checksum)

	return buf, nil
}

func (c *CodecICMP) NextLayer() Codec {
	return c.Payload
}

func (c *CodecICMP) String() string {
	return fmt.Sprintf("&CodecICMP{Type:%d, Code:%d, Csum:0x%04x, Rsvd:0x%08x, %v}", c.Type, c.Code, c.Checksum, c.Reserved, c.Payload)
}

func (c *CodecICMPv6) Decode(buf []byte) error {
	if len(buf) < 8 {
		return errors.New("gophertun: invalid ICMP packet")
	}
	c.Type = buf[0]
	c.Code = buf[1]
	c.Checksum = binary.BigEndian.Uint16(buf[2:4])
	if c.Checksum != 0 {
		switch c.pseudoHeader.(type) {
		case *CodecIPv6:
			pseudoHeader, err := c.pseudoHeader.encodePseudoHeader()
			if err != nil {
				return err
			}
			binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(len(buf)))
			pseudoHeader[39] = 58
			pseudoHeader = append(pseudoHeader, buf...)
			if checksum(pseudoHeader) != 0 {
				return errors.New("gophertun: ICMPv6 checksum error")
			}
		default:
			return errors.New("gophertun: ICMPv6 checksum error")
		}
	}
	c.Omni = binary.BigEndian.Uint32(buf[4:8])
	c.Payload = &CodecRaw{buf[8:], nil}
	return nil
}

func (c *CodecICMPv6) Encode() ([]byte, error) {
	payload, err := c.Payload.Encode()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 8+len(payload))
	buf[0] = c.Type
	buf[1] = c.Code
	binary.BigEndian.PutUint32(buf[4:8], c.Omni)
	copy(buf[8:], payload)

	c.Checksum = 0
	switch c.pseudoHeader.(type) {
	case *CodecIPv6:
		pseudoHeader, err := c.pseudoHeader.encodePseudoHeader()
		if err != nil {
			return nil, err
		}
		binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(len(buf)))
		pseudoHeader[39] = 58
		pseudoHeader = append(pseudoHeader, buf...)
		c.Checksum = checksum(pseudoHeader)
	}
	binary.BigEndian.PutUint16(buf[:4], c.Checksum)

	return buf, nil
}

func (c *CodecICMPv6) NextLayer() Codec {
	return c.Payload
}

func (c *CodecICMPv6) setPseudoHeader(pseudoHeader hasPseudoHeader) {
	c.pseudoHeader = pseudoHeader
}

func (c *CodecICMPv6) String() string {
	return fmt.Sprintf("&CodecICMPv6{Type:%d, Code:%d, Csum:0x%04x, Rsvd:0x%08x, %v}", c.Type, c.Code, c.Checksum, c.Omni, c.Payload)
}
