package allocator

import (
	"container/heap"
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// IPHeap implements a min-heap for IP addresses (net.IP)
type IPHeap []net.IP

func (h IPHeap) Len() int { return len(h) }
func (h IPHeap) Less(i, j int) bool {
	return bytesCompare(h[i], h[j]) < 0
}
func (h IPHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *IPHeap) Push(x interface{}) {
	*h = append(*h, x.(net.IP))
}
func (h *IPHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

func bytesCompare(a, b net.IP) int {
	a4 := a.To16()
	b4 := b.To16()
	return strings.Compare(string(a4), string(b4))
}


func ipToKey(ip net.IP) string {
	return "/ip-pool/available/" + ip.String()
}

func takenKey(ip net.IP) string {
	return "/ip-pool/taken/" + ip.String()
}

func LoadAvailableIPs(ctx context.Context, cli *clientv3.Client) ([]net.IP, error) {
	resp, err := cli.Get(ctx, "/ip-pool/available/", clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, kv := range resp.Kvs {
		key := string(kv.Key)
		ipStr := strings.TrimPrefix(key, "/ip-pool/available/")
		ip := net.ParseIP(ipStr)
		if ip == nil {
			log.Printf("invalid IP in etcd key: %s", key)
			continue
		}
		ips = append(ips, ip)
	}

	// Sort for deterministic heap build (not required, but good)
	sort.Slice(ips, func(i, j int) bool {
		return bytesCompare(ips[i], ips[j]) < 0
	})

	return ips, nil
}

func WatchAvailableIPs(ctx context.Context, cli *clientv3.Client, ipHeap *IPHeap) {
	rch := cli.Watch(ctx, "/ip-pool/available/", clientv3.WithPrefix())
	for wresp := range rch {
		for _, ev := range wresp.Events {
			ipStr := strings.TrimPrefix(string(ev.Kv.Key), "/ip-pool/available/")
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}

			switch ev.Type {
			case clientv3.EventTypePut:
				// Add new available IP to heap
				heap.Push(ipHeap, ip)
				log.Printf("IP available: %s", ip)
			case clientv3.EventTypeDelete:
				// Remove IP from heap if deleted (allocation)
				RemoveIPFromHeap(ipHeap, ip)
				log.Printf("IP allocated or removed: %s", ip)
			}
		}
	}
}

func RemoveIPFromHeap(ipHeap *IPHeap, ip net.IP) {
	for i, val := range *ipHeap {
		if val.Equal(ip) {
			heap.Remove(ipHeap, i)
			return
		}
	}
}

func AllocateIP(ctx context.Context, cli *clientv3.Client, ipHeap *IPHeap, publicKey string) (net.IP, error) {
	if ipHeap.Len() == 0 {
		return nil, fmt.Errorf("no available IPs")
	}

	ip := heap.Pop(ipHeap).(net.IP)
	availKey := ipToKey(ip)
	takeKey := takenKey(ip)

	txn := cli.Txn(ctx)
	// Transaction condition: available key must exist
	txnResp, err := txn.If(clientv3.Compare(clientv3.Version(availKey), ">", 0)).
		Then(
			clientv3.OpDelete(availKey),
			clientv3.OpPut(takeKey, publicKey),
		).
		Commit()

	if err != nil {
		// On error, push IP back to heap to keep local state consistent
		heap.Push(ipHeap, ip)
		return nil, err
	}

	if !txnResp.Succeeded {
		// If the available key doesn't exist (race condition), reload heap and retry or return error
		heap.Push(ipHeap, ip)
		return nil, fmt.Errorf("ip %s is already taken", ip.String())
	}

	return ip, nil
}

func ReleaseIP(ctx context.Context, cli *clientv3.Client, ip net.IP) error {
	availKey := ipToKey(ip)
	takeKey := takenKey(ip)

	txn := cli.Txn(ctx)
	_, err := txn.If(clientv3.Compare(clientv3.Version(takeKey), ">", 0)).
		Then(
			clientv3.OpDelete(takeKey),
			clientv3.OpPut(availKey, ""),
		).
		Commit()
	return err
}