package types

import (
	"fmt"
	"net"
	"strings"
)

type Networks []*net.IPNet

func (networks *Networks) String() string {
	sb := strings.Builder{}
	for i, net := range *networks {
		sb.WriteString(net.String())
		if i < len(*networks)-1 {
			sb.WriteString(",")
		}
	}
	return sb.String()
}

func (networks *Networks) Set(value string) error {
	valueList := strings.Split(value, ",")
	// preallocate size
	*networks = make(Networks, 0, len(valueList))
	var n *net.IPNet
	var err error
	for _, v := range valueList {
		if strings.Contains(v, "/") {
			_, n, err = net.ParseCIDR(v)
			if err != nil {
				return err
			}
		} else {
			ipAddr := net.ParseIP(v)
			if ipAddr == nil {
				return fmt.Errorf("unable to parse ip address: '%s'", ipAddr)
			}
			n = &net.IPNet{
				IP:   ipAddr,
				Mask: []byte{255, 255, 255, 255},
			}
		}
		*networks = append(*networks, n)
	}
	return nil
}
