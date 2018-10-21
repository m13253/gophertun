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
	"errors"
	"net"
	"os"
)

type Tunnel interface {
	AddIPAddresses(addresses []*IPAddress) (int, error)
	Close() error
	MTU() (int, error)
	Name() (string, error)
	NativeFormat() PayloadFormat
	Open(outputFormat PayloadFormat) error
	OutputFormat() PayloadFormat
	RawFile() *os.File
	Read() (*Packet, error)
	SetMTU(mtu int) error
	Write(packet *Packet, pmtud bool) error
}

type TunnelConfig interface {
	Create() (Tunnel, error)
}

type IPAddress struct {
	Net  *net.IPNet
	Peer *net.IPNet
}

type Packet struct {
	Format    PayloadFormat
	EtherType EtherType
	Payload   []byte
	Extra     []byte
}

type PayloadFormat int

const (
	FormatUnknown PayloadFormat = iota
	FormatIP
	FormatEthernet
)

type EtherType uint16

const (
	EtherTypeIPv4 EtherType = 0x0800
	EtherTypeARP  EtherType = 0x0806
	EtherTypeIPv6 EtherType = 0x86dd
)

const (
	DefaultMRU                   = 65536
	DefaultMTU                   = 1500
	DefaultTTL                   = 64
	DefaultPostProcessBufferSize = 16
	EthernetHeaderSize           = 14
)

var (
	ErrUnsupportedFeature  = errors.New("gophertun: feature unsupported on this platform")
	ErrUnsupportedProtocol = errors.New("gophertun: protocol unsupported")
)
