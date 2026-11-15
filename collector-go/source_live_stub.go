//go:build !linux || !cgo

package main

import "fmt"

func openLive(iface string) (PacketSource, error) {
	return nil, fmt.Errorf("live capture requires linux, cgo, and libpcap (interface %q)", iface)
}
