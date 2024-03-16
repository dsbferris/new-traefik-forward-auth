package types

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

type Networks []*net.IPNet

// UnmarshalFlag converts a string to a CookieDomain
func (n *Networks) UnmarshalFlag(value string) error {
	return n.Set(value)
}

// MarshalFlag converts a CookieDomain to a string
func (n *Networks) MarshalFlag() (string, error) {
	return n.String(), nil
}

func (n Networks) ConatainsIp(ip string) (bool, error) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false, fmt.Errorf("invalid ip address: '%s'", ip)
	}

	for _, n := range n {
		if n.Contains(addr) {
			return true, nil
		}
	}

	return false, nil
}

// implements [encoding.TextMarshaler]
func (n Networks) MarshalText() (value []byte, err error) {
	return []byte(n.String()), nil
}

// implements [encoding.TextUnmarshaler]
func (n *Networks) UnmarshalText(value []byte) error {
	return n.Set(string(value))
}

// implements [flag.Value]
func (n Networks) String() string {
	sb := strings.Builder{}
	for i, net := range n {
		sb.WriteString(net.String())
		if i < len(n)-1 {
			sb.WriteByte(',')
		}
	}
	return sb.String()
}

// implements [flag.Value]
func (n *Networks) Set(value string) error {
	valueList := strings.Split(value, ",")
	networks := make([]*net.IPNet, len(valueList))
	for i, v := range valueList {
		if !strings.Contains(v, "/") {
			v += "/32"
		}
		_, net, err := net.ParseCIDR(v)
		if err != nil {
			return errors.Join(fmt.Errorf("single ip addresses automatically get /32 added"), err)
		}
		networks[i] = net
	}
	*n = networks
	return nil
}
