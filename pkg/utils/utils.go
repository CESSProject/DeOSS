package utils

import (
	"fmt"
	"net"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

func Ternary(a, b int64) int64 {
	if a > b {
		return b
	}
	return a
}

func ParseMultiaddrs(domain string) ([]string, error) {
	var result = make([]string, 0)
	var realDns = make([]string, 0)

	addr, err := ma.NewMultiaddr(domain)
	if err == nil {
		_, err = peer.AddrInfoFromP2pAddr(addr)
		if err == nil {
			result = append(result, domain)
			return result, nil
		}
	}

	dnsnames, err := net.LookupTXT(domain)
	if err != nil {
		return result, err
	}

	for _, v := range dnsnames {
		if strings.Contains(v, "ip4") && strings.Contains(v, "tcp") && strings.Count(v, "=") == 1 {
			result = append(result, strings.TrimPrefix(v, "dnsaddr="))
		}
	}

	trims := strings.Split(domain, ".")
	domainname := fmt.Sprintf("%s.%s", trims[len(trims)-2], trims[len(trims)-1])

	for _, v := range dnsnames {
		trims = strings.Split(v, "/")
		for _, vv := range trims {
			if strings.Contains(vv, domainname) {
				realDns = append(realDns, vv)
				break
			}
		}
	}

	for _, v := range realDns {
		dnses, err := net.LookupTXT("_dnsaddr." + v)
		if err != nil {
			continue
		}
		for i := 0; i < len(dnses); i++ {
			if strings.Contains(dnses[i], "ip4") && strings.Contains(dnses[i], "tcp") && strings.Count(dnses[i], "=") == 1 {
				var multiaddr = strings.TrimPrefix(dnses[i], "dnsaddr=")
				result = append(result, multiaddr)
			}
		}
	}

	return result, nil
}
