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

const (
	_FILE_DEVICE_UNKNOWN = 0x00000022
	_METHOD_BUFFERED     = 0
	_FILE_ANY_ACCESS     = 0
)

var (
	_TAP_WIN_IOCTL_GET_MAC               = _TAP_WIN_CONTROL_CODE(1, _METHOD_BUFFERED)
	_TAP_WIN_IOCTL_GET_VERSION           = _TAP_WIN_CONTROL_CODE(2, _METHOD_BUFFERED)
	_TAP_WIN_IOCTL_GET_MTU               = _TAP_WIN_CONTROL_CODE(3, _METHOD_BUFFERED)
	_TAP_WIN_IOCTL_GET_INFO              = _TAP_WIN_CONTROL_CODE(4, _METHOD_BUFFERED)
	_TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT = _TAP_WIN_CONTROL_CODE(5, _METHOD_BUFFERED)
	_TAP_WIN_IOCTL_SET_MEDIA_STATUS      = _TAP_WIN_CONTROL_CODE(6, _METHOD_BUFFERED)
	_TAP_WIN_IOCTL_CONFIG_DHCP_MASQ      = _TAP_WIN_CONTROL_CODE(7, _METHOD_BUFFERED)
	_TAP_WIN_IOCTL_GET_LOG_LINE          = _TAP_WIN_CONTROL_CODE(8, _METHOD_BUFFERED)
	_TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT   = _TAP_WIN_CONTROL_CODE(9, _METHOD_BUFFERED)
	_TAP_WIN_IOCTL_CONFIG_TUN            = _TAP_WIN_CONTROL_CODE(10, _METHOD_BUFFERED)
)

const (
	_ADAPTER_KEY             = `SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`
	_NETWORK_CONNECTIONS_KEY = `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}`
	_USERMODEDEVICEDIR       = `\\.\Global\`
	_SYSDEVICEDIR            = `\Device\`
	_USERDEVICEDIR           = `\DosDevices\Global\`
	_TAP_WIN_SUFFIX          = ".tap"
)

func _CTL_CODE(deviceType, function, method, access uint32) uint32 {
	return (deviceType << 16) | (access << 14) | (function << 2) | method
}

func _TAP_WIN_CONTROL_CODE(request, method uint32) uint32 {
	return _CTL_CODE(_FILE_DEVICE_UNKNOWN, request, method, _FILE_ANY_ACCESS)
}
