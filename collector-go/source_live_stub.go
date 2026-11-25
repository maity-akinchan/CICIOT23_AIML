//go:build !windows && (!linux || !cgo)

package main

import (
	"fmt"
	"io"
)

func listInterfaces(_ io.Writer) error {
	return fmt.Errorf("interface listing requires a live build for Linux (CGO/libpcap) or Windows (Npcap)")
}

func openLive(iface string) (PacketSource, error) {
	return nil, fmt.Errorf("live capture requires a Linux CGO/libpcap or Windows Npcap build (interface %q)", iface)
}
