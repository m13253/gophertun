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
	"os"
)

type VxlanConfig struct {
	VxlanConn           net.PacketConn
	VxlanNetworkID      uint32
	VxlanTunnelEndpoint net.Addr
}

type VxlanImpl struct {
	conn         net.PacketConn
	vni          uint32
	vtep         net.Addr
	outputFormat PayloadFormat
	hwAddr       net.HardwareAddr
	mtu          int
	buffer       chan *Packet
}

func (c *VxlanConfig) Create() (Tunnel, error) {
	return &VxlanImpl{
		conn:   c.VxlanConn,
		vni:    c.VxlanNetworkID,
		vtep:   c.VxlanTunnelEndpoint,
		mtu:    1430,
		buffer: make(chan *Packet, DefaultPostProcessBufferSize),
	}, nil
}

func (t *VxlanImpl) AddIPAddresses(addresses []*IPAddress) (int, error) {
	return 0, ErrUnsupportedFeature
}

func (t *VxlanImpl) Close() error {
	return t.conn.Close()
}

func (t *VxlanImpl) MTU() (int, error) {
	return t.mtu, nil
}

func (t *VxlanImpl) Name() (string, error) {
	addr := t.conn.LocalAddr()
	if addr != nil {
		return addr.String(), nil
	}
	return "", ErrUnsupportedFeature
}

func (t *VxlanImpl) NativeFormat() PayloadFormat {
	return FormatEthernet
}

func (t *VxlanImpl) Open(outputFormat PayloadFormat) error {
	switch outputFormat {
	case FormatUnknown, FormatIP:
		t.outputFormat = FormatIP
	case FormatEthernet:
		t.outputFormat = FormatEthernet
	default:
		return ErrUnsupportedFeature
	}
	t.hwAddr = generateMACAddress()
	return nil
}

func (t *VxlanImpl) OutputFormat() PayloadFormat {
	return t.outputFormat
}

func (t *VxlanImpl) RawFile() (*os.File, error) {
	if udpConn, ok := t.conn.(*net.UDPConn); ok {
		return udpConn.File()
	}
	return nil, ErrUnsupportedFeature
}

func (t *VxlanImpl) Read() (*Packet, error) {
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

func (t *VxlanImpl) readRaw() (*Packet, error) {
	buf := make([]byte, DefaultMRU+EthernetHeaderSize+8)
retry:
	n, _, err := t.conn.ReadFrom(buf[:])
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	if n < 8 {
		goto retry
	}
	if buf[0]&0x08 == 0 || binary.BigEndian.Uint32(buf[4:8])>>8 != t.vni {
		goto retry
	}
	etherType := EtherType(0)
	if n >= EthernetHeaderSize+8 {
		etherType = EtherType(binary.BigEndian.Uint16(buf[20:22]))
	}
	packet := &Packet{
		Format:    FormatEthernet,
		EtherType: etherType,
		Payload:   buf[8:n],
	}
	packet, err = packet.ConvertTo(t.outputFormat, t.hwAddr)
	if err != nil {
		return nil, err
	}
	if packet == nil {
		goto retry
	}
	return packet, nil
}

func (t *VxlanImpl) SetMTU(mtu int) error {
	if mtu <= 0 {
		return errors.New("gophertun: invalid MTU")
	}
	t.mtu = mtu
	return nil
}

func (t *VxlanImpl) Write(packet *Packet, pmtud bool) error {
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

func (t *VxlanImpl) writeRaw(packet *Packet) (needFrag bool, err error) {
	packet, err = packet.ConvertTo(FormatEthernet, t.hwAddr)
	if err != nil {
		return false, err
	}
	if packet == nil {
		return false, nil
	}
	buf := make([]byte, len(packet.Payload)+8)
	buf[0] = 0x08
	binary.BigEndian.PutUint32(buf[4:8], t.vni<<8)
	copy(buf[8:], packet.Payload)
	_, err = t.conn.WriteTo(buf, t.vtep)
	if err != nil {
		return false, err
	}
	return false, nil
}
