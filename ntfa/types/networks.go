package types

import (
	"fmt"
	"net"
	"strings"
)

type Networks []*net.IPNet

func (networks Networks) ConatainsIp(ip string) (bool, error) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false, fmt.Errorf("invalid ip address: '%s'", ip)
	}

	for _, networks := range networks {
		if networks.Contains(addr) {
			return true, nil
		}
	}

	return false, nil
}

// UnmarshalFlag converts a string to a CookieDomain
func (networks *Networks) UnmarshalFlag(value string) error {
	return networks.Set(value)
}

// MarshalFlag converts a CookieDomain to a string
func (networks *Networks) MarshalFlag() (string, error) {
	return networks.String(), nil
}

// implements [flag.Value]
func (networks Networks) String() string {
	sb := strings.Builder{}
	for i, net := range networks {
		sb.WriteString(net.String())
		if i < len(networks)-1 {
			sb.WriteByte(',')
		}
	}
	return sb.String()
}

// implements [flag.Value]
func (networks *Networks) Set(value string) error {
	for _, v := range strings.Split(value, ",") {
		if len(v) <= 0 {
			continue
		}
		// adding the /32 allows for use of parseCIDR
		if !strings.Contains(v, "/") {
			v += "/32"
		}
		_, net, err := net.ParseCIDR(v)
		if err != nil {
			fmt.Println("note: single ip addresses automatically get the suffix \"/32\" added")
			return err
		}
		*networks = append(*networks, net)
	}
	return nil
}
