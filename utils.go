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

func dupBytes(bytes []byte) []byte {
	if len(bytes) == 0 {
		return nil
	}
	result := make([]byte, len(bytes))
	copy(result, bytes)
	return result
}

func checksum(buf []byte) uint16 {
	if len(buf) > 0xffff {
		panic("gophertun: checksum length > 65535 unimplemented yet")
	}
	sum := uint32(0)
	i := 0
	for ; i < len(buf)-1; i += 2 {
		sum += uint32(buf[i]) << 8
		sum += uint32(buf[i+1])
	}
	if i < len(buf) {
		sum += uint32(buf[len(buf)-1])
	}
	return ^uint16(sum>>16 + sum)
}
