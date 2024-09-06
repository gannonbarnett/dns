package main

import (
	"github.com/gannonbarnett/dns"
)

func main() {
	dnsServer := dns.NewDnsServer()
	dnsServer.Start()
}
