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
	"os"
)

type TunTapImpl struct {
}

func (c *TunTapConfig) Create() (Tunnel, error) {
	return nil, UnsupportedFeatureError
}

func (t *TunTapImpl) AddIPAddresses(addresses []*IPAddress) (int, error) {
	return 0, UnsupportedFeatureError
}

func (t *TunTapImpl) Close() error {
	return UnsupportedFeatureError
}

func (t *TunTapImpl) MTU() (int, error) {
	return DefaultMTU, UnsupportedFeatureError
}

func (t *TunTapImpl) Name() (string, error) {
	return "", UnsupportedFeatureError
}

func (t *TunTapImpl) NativeFormat() PayloadFormat {
	return FormatUnknown
}

func (t *TunTapImpl) Open(outputFormat PayloadFormat) error {
	return UnsupportedFeatureError
}

func (t *TunTapImpl) OutputFormat() PayloadFormat {
	return FormatUnknown
}

func (t *TunTapImpl) RawFile() *os.File {
	return nil
}

func (t *TunTapImpl) Read() (*Packet, error) {
	return nil, UnsupportedFeatureError
}

func (t *TunTapImpl) SetMTU(mtu int) error {
	return UnsupportedFeatureError
}

func (t *TunTapImpl) Write(packet *Packet, pmtud bool) error {
	return UnsupportedFeatureError
}
