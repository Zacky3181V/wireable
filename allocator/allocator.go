package allocator 

import (
	"errors"
	"net"
	"sync"
)

type IPAllocator struct {
	baseIP   net.IP
	mask     *net.IPNet
	current  net.IP
	allocated map[string]bool
	mu       sync.Mutex
}

func NewIPAllocator(cidr string) (*IPAllocator, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Start from the first usable address (e.g., 10.0.0.2)
	start := make(net.IP, len(ip.To4()))
	copy(start, ip.To4())
	start[3]++ // skip .0
	start[3]++ // skip .1 → start at .2

	return &IPAllocator{
		baseIP:   ip,
		mask:     ipnet,
		current:  start,
		allocated: make(map[string]bool),
	}, nil
}

func (a *IPAllocator) Allocate() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for {
		ipStr := a.current.String()
		if !a.allocated[ipStr] && a.mask.Contains(a.current) {
			a.allocated[ipStr] = true

			// Prepare next
			a.incrementIP()

			return ipStr, nil
		}

		// Check overflow
		if !a.mask.Contains(a.current) {
			return "", errors.New("no IPs left in subnet")
		}

		a.incrementIP()
	}
}

func (a *IPAllocator) incrementIP() {
	for i := len(a.current) - 1; i >= 0; i-- {
		a.current[i]++
		if a.current[i] != 0 {
			break
		}
	}
}

