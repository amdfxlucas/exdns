package util

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

// Bigger than we need, not too big to worry about overflow
const big = 0xFFFFFF

// Decimal to integer.
// Returns number, characters consumed, success.
func dtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= big {
			return big, i, false
		}
	}
	if i == 0 {
		return 0, 0, false
	}
	return n, i, true
}

// Hexadecimal to integer.
// Returns number, characters consumed, success.
func xtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s); i++ {
		if '0' <= s[i] && s[i] <= '9' {
			n *= 16
			n += int(s[i] - '0')
		} else if 'a' <= s[i] && s[i] <= 'f' {
			n *= 16
			n += int(s[i]-'a') + 10
		} else if 'A' <= s[i] && s[i] <= 'F' {
			n *= 16
			n += int(s[i]-'A') + 10
		} else {
			break
		}
		if n >= big {
			return 0, i, false
		}
	}
	if i == 0 {
		return 0, i, false
	}
	return n, i, true
}

// Parse IPv4 address (d.d.d.d).
func ParseIPv4(s string) net.IP {
	var p [net.IPv4len]byte
	for i := 0; i < net.IPv4len; i++ {
		if len(s) == 0 {
			// Missing octets.
			return nil
		}
		if i > 0 {
			if s[0] != '.' {
				return nil
			}
			s = s[1:]
		}
		n, c, ok := dtoi(s)
		if !ok || n > 0xFF {
			return nil
		}
		if c > 1 && s[0] == '0' {
			// Reject non-zero components with leading zeroes.
			return nil
		}
		s = s[c:]
		p[i] = byte(n)
	}
	if len(s) != 0 {
		return nil
	}
	return net.IPv4(p[0], p[1], p[2], p[3])
}

// computes the inverse address for rDNS lookup
// i.e. 19-ffaa:1:1067,[127.0.0.1] => 1.0.0.127.in-addr.19-ffaa-1-1067.scion.arpa.
func ReverseSCIONAddr(scaddr string) (string, error) {
	addr, err := pan.ParseUDPAddr(scaddr)
	if err != nil {
		// if it wasnt a valid SCION address, we were passed
		// just act as the identity Fcn
		return scaddr, err
	}
	var invName string
	invIA := strings.Replace(addr.IA.String(), ":", "-", -1)
	var revIP string
	if addr.IP.Is4() {
		str := addr.IP.String()
		revIP, err = InvertIPv4(str)
		if err != nil {
			return scaddr, err
		}
		invName = revIP + ".in-addr." + invIA + ".scion.arpa"
		return invName, nil
	} else if addr.IP.Is6() {
		tmpIP, err := InvertIPv6(addr.IP.StringExpanded())
		if err != nil {
			return scaddr, err
		}
		revIP = strings.Replace(tmpIP, ":", ".", -1)
		invName = revIP + ".ipv6." + invIA + ".scion.arpa"
		return invName, nil
	}
	return scaddr, errors.New("your AS's host addressing scheme is neither IPv4 nor 6 and not supported for rDNS lookup yet")
}

func ParseIPv6(s string) (ip net.IP) {
	ip = make(net.IP, net.IPv6len)
	ellipsis := -1 // position of ellipsis in ip

	// Might have leading ellipsis
	if len(s) >= 2 && s[0] == ':' && s[1] == ':' {
		ellipsis = 0
		s = s[2:]
		// Might be only ellipsis
		if len(s) == 0 {
			return ip
		}
	}

	// Loop, parsing hex numbers followed by colon.
	i := 0
	for i < net.IPv6len {
		// Hex number.
		n, c, ok := xtoi(s)
		if !ok || n > 0xFFFF {
			return nil
		}

		// If followed by dot, might be in trailing IPv4.
		if c < len(s) && s[c] == '.' {
			if ellipsis < 0 && i != net.IPv6len-net.IPv4len {
				// Not the right place.
				return nil
			}
			if i+net.IPv4len > net.IPv6len {
				// Not enough room.
				return nil
			}
			ip4 := ParseIPv4(s)
			if ip4 == nil {
				return nil
			}
			ip[i] = ip4[12]
			ip[i+1] = ip4[13]
			ip[i+2] = ip4[14]
			ip[i+3] = ip4[15]
			s = ""
			i += net.IPv4len
			break
		}

		// Save this 16-bit chunk.
		ip[i] = byte(n >> 8)
		ip[i+1] = byte(n)
		i += 2

		// Stop at end of string.
		s = s[c:]
		if len(s) == 0 {
			break
		}

		// Otherwise must be followed by colon and more.
		if s[0] != ':' || len(s) == 1 {
			return nil
		}
		s = s[1:]

		// Look for ellipsis.
		if s[0] == ':' {
			if ellipsis >= 0 { // already have one
				return nil
			}
			ellipsis = i
			s = s[1:]
			if len(s) == 0 { // can be at end
				break
			}
		}
	}

	// Must have used entire string.
	if len(s) != 0 {
		return nil
	}

	// If didn't parse enough, expand ellipsis.
	if i < net.IPv6len {
		if ellipsis < 0 {
			return nil
		}
		n := net.IPv6len - i
		for j := i - 1; j >= ellipsis; j-- {
			ip[j+n] = ip[j]
		}
		for j := ellipsis + n - 1; j >= ellipsis; j-- {
			ip[j] = 0
		}
	} else if ellipsis >= 0 {
		// Ellipsis must represent at least one 0 group.
		return nil
	}
	return ip
}

func InvertIPv4(ip string) (invertedIP string, err error) {

	octets := strings.Split(ip, ".")
	if len(octets) != 4 {
		return "", fmt.Errorf("%v is not an IPV4", ip)
	}

	for i := 3; i >= 0; i-- {
		invertedIP += octets[i]
		if i != 0 {
			invertedIP += "."
		}
	}
	return invertedIP, nil
}

func InvertIPv6(ip string) (invertedIP string, err error) {

	octets := strings.Split(ip, ":")
	if len(octets) != 15 {
		return "", fmt.Errorf("%v is not an IPV6", ip)
	}

	for i := 15; i >= 0; i-- {
		invertedIP += octets[i]
		if i != 0 {
			invertedIP += ":"
		}
	}
	return invertedIP, nil
}
