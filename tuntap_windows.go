// +build windows

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
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

type TunTapImpl struct {
	f            *os.File
	name         string
	outputFormat PayloadFormat
	hwAddr       net.HardwareAddr
	buffer       chan *Packet
}

func (c *TunTapConfig) findAllTunnels() ([]string, error) {
	adapterIDRegexp := regexp.MustCompile(`\d{4}`)
	componentIDRegexp := regexp.MustCompile(`tap\d{4}`)

	netprop, err := registry.OpenKey(registry.LOCAL_MACHINE, _ADAPTER_KEY, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	adapters, err := netprop.ReadSubKeyNames(0)
	results := make([]string, 0, len(adapters))
	for _, i := range adapters {
		if !adapterIDRegexp.MatchString(i) {
			continue
		}
		adapter, err := registry.OpenKey(registry.LOCAL_MACHINE, filepath.Join(_ADAPTER_KEY, i), registry.QUERY_VALUE)
		if err != nil {
			log.Printf("Warning: gophertun: %s\n", err)
			continue
		}
		componentID, _, err := adapter.GetStringValue("ComponentId")
		if err != nil {
			log.Printf("Warning: gophertun: %s\n", err)
		}
		if !componentIDRegexp.MatchString(componentID) {
			continue
		}
		netCfgInstanceID, _, err := adapter.GetStringValue("NetCfgInstanceId")
		if err != nil {
			return nil, err
		}
		results = append(results, netCfgInstanceID)
	}
	return results, nil
}

func (c *TunTapConfig) tryOpenTunnel() (*os.File, string, error) {
	if c.NameHint != "" {
		f, err := os.Open(_USERMODEDEVICEDIR + c.NameHint + _TAP_WIN_SUFFIX)
		if err == nil {
			return f, c.NameHint, err
		}
	}
	if c.NameHint == "" || c.AllowNameSuffix {
		candidates, err := c.findAllTunnels()
		if err != nil {
			return nil, "", err
		}
		for _, i := range candidates {
			f, err := os.Open(_USERMODEDEVICEDIR + i + _TAP_WIN_SUFFIX)
			if err == nil {
				return f, i, err
			}
		}
	}
	return nil, "", errors.New("gophertun: no TAP-Windows devices available")
}

func (c *TunTapConfig) Create() (Tunnel, error) {
	f, name, err := c.tryOpenTunnel()
	if err != nil {
		return nil, err
	}
	return &TunTapImpl{
		f:      f,
		name:   name,
		buffer: make(chan *Packet, DefaultPostProcessBufferSize),
	}, nil
}

func (t *TunTapImpl) AddIPAddresses(addresses []*IPAddress) (int, error) {
	return 0, ErrUnsupportedFeature
}

func (t *TunTapImpl) Close() error {
	mediaStatus := int32(0)
	bytesReturned := uint32(0)
	_ = syscall.DeviceIoControl(syscall.Handle(t.f.Fd()), _TAP_WIN_IOCTL_SET_MEDIA_STATUS, (*byte)(unsafe.Pointer(&mediaStatus)), uint32(unsafe.Sizeof(mediaStatus)), (*byte)(unsafe.Pointer(&mediaStatus)), uint32(unsafe.Sizeof(mediaStatus)), &bytesReturned, nil)

	return t.f.Close()
}

func (t *TunTapImpl) MTU() (int, error) {
	mtu := uint32(0)
	bytesReturned := uint32(0)
	err := syscall.DeviceIoControl(syscall.Handle(t.f.Fd()), _TAP_WIN_IOCTL_GET_MTU, (*byte)(unsafe.Pointer(&mtu)), uint32(unsafe.Sizeof(mtu)), (*byte)(unsafe.Pointer(&mtu)), uint32(unsafe.Sizeof(mtu)), &bytesReturned, nil)
	if err != nil {
		return DefaultMTU, os.NewSyscallError("DeviceIoControl (TAP_WIN_IOCTL_GET_MTU)", err)
	}
	return int(mtu), nil
}

func (t *TunTapImpl) Name() (string, error) {
	return t.name, nil
}

func (t *TunTapImpl) NativeFormat() PayloadFormat {
	return FormatEthernet
}

func (t *TunTapImpl) Open(outputFormat PayloadFormat) error {
	switch outputFormat {
	case FormatUnknown, FormatIP:
		t.outputFormat = FormatIP
	case FormatEthernet:
		t.outputFormat = FormatEthernet
	default:
		return ErrUnsupportedFeature
	}
	t.hwAddr = generateMACAddress()

	mediaStatus := int32(1)
	bytesReturned := uint32(0)
	err := syscall.DeviceIoControl(syscall.Handle(t.f.Fd()), _TAP_WIN_IOCTL_SET_MEDIA_STATUS, (*byte)(unsafe.Pointer(&mediaStatus)), uint32(unsafe.Sizeof(mediaStatus)), (*byte)(unsafe.Pointer(&mediaStatus)), uint32(unsafe.Sizeof(mediaStatus)), &bytesReturned, nil)
	if err != nil {
		return os.NewSyscallError("DeviceIoControl (TAP_WIN_IOCTL_SET_MEDIA_STATUS)", err)
	}

	return nil
}

func (t *TunTapImpl) OutputFormat() PayloadFormat {
	return t.outputFormat
}

func (t *TunTapImpl) RawFile() (*os.File, error) {
	return t.f, nil
}

func (t *TunTapImpl) readRaw() (*Packet, error) {
	buf := make([]byte, DefaultMRU+EthernetHeaderSize)
retry:
	n, err := t.f.Read(buf[:])
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	if n < 4 {
		goto retry
	}
	etherType := EtherType(0)
	if n >= EthernetHeaderSize+8 {
		etherType = EtherType(binary.BigEndian.Uint16(buf[12:14]))
	}
	packet := &Packet{
		Format:    FormatEthernet,
		EtherType: etherType,
		Payload:   buf[:n],
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

func (t *TunTapImpl) SetMTU(mtu int) error {
	return ErrUnsupportedFeature
}

func (t *TunTapImpl) writeRaw(packet *Packet) (needFrag bool, err error) {
	packet, err = packet.ConvertTo(FormatEthernet, t.hwAddr)
	if err != nil {
		return false, err
	}
	if packet == nil {
		return false, nil
	}
	_, err = t.f.Write(packet.Payload)
	if err != nil {
		return false, err
	}
	return false, nil
}
