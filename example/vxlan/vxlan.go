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

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	gophertun "../.."
)

func main() {
	var err error
	listenAddr, vni, vtepAddr := "[ff02::15c]:4789", uint64(64384), "[ff02::15c]:4789"
	if len(os.Args) > 1 {
		listenAddr = os.Args[1]
	}
	if len(os.Args) > 2 {
		vni, err = strconv.ParseUint(os.Args[2], 0, 24)
		if err != nil {
			log.Fatalln(err)
		}
	}
	if len(os.Args) > 3 {
		vtepAddr = os.Args[3]
	}
	laddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Fatalln(err)
	}
	var conn net.PacketConn
	if laddr.IP.IsMulticast() {
		conn, err = net.ListenMulticastUDP("udp", nil, laddr)
	} else {
		conn, err = net.ListenUDP("udp", laddr)
	}
	if err != nil {
		log.Fatalln(err)
	}
	vtep, err := net.ResolveUDPAddr("udp", vtepAddr)
	if err != nil {
		log.Fatalln(err)
	}
	c := &gophertun.VxlanConfig{
		VxlanConn:           conn,
		VxlanNetworkID:      uint32(vni),
		VxlanTunnelEndpoint: vtep,
	}
	t, err := c.Create()
	if err != nil {
		log.Fatalln(err)
	}
	defer t.Close()
	name, err := t.Name()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Listen: %s\n", name)
	fmt.Printf("VNI:    %d\n", vni)
	fmt.Printf("VTEP:   %s\n", vtep)
	mtu, err := t.MTU()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("MTU:    %d\n", mtu)
	err = t.Open(gophertun.FormatIP)
	for {
		p, err := t.Read()
		if err != nil {
			log.Fatalln(err)
		}
		if p == nil {
			break
		}
		fmt.Printf("EtherType: %04x Payload: %x Extra: %x\n", p.EtherType, p.Payload, p.Extra)
	}
}
