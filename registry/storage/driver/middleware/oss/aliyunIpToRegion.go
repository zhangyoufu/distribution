package middleware

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	patricia "github.com/kentik/patricia"
	patricia_string_tree "github.com/kentik/patricia/string_tree"
)

// nolint:golint
type aliyunIpToRegion struct {
	jsonUrl string // nolint:golint
	tree    atomic.Pointer[patricia_string_tree.TreeV4]
}

// nolint:golint
func newAliyunIpToRegion(jsonUrl string, refreshInterval time.Duration) (*aliyunIpToRegion, error) {
	this := &aliyunIpToRegion{
		jsonUrl: jsonUrl,
	}
	err := this.refresh()
	if err != nil {
		return nil, err
	}
	go func() {
		ticker := time.NewTicker(refreshInterval)
		for {
			<-ticker.C
			err := this.refresh()
			if err != nil {
				log.Printf("aliyunIpToRegion refresh failed: %v", err)
			}
		}
	}()
	return this, nil
}

// nolint:golint
func (this *aliyunIpToRegion) refresh() error {
	rsp, err := http.Get(this.jsonUrl)
	if err != nil {
		return err
	}
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", rsp.StatusCode)
	}
	jsonData, err := io.ReadAll(rsp.Body)
	_ = rsp.Body.Close()
	if err != nil {
		return err
	}
	regions := map[string][]string{}
	err = json.Unmarshal(jsonData, &regions)
	if err != nil {
		return err
	}
	tree := patricia_string_tree.NewTreeV4()
	for regionId, cidrList := range regions { // nolint:golint
		for _, cidrString := range cidrList {
			_, ipNet, err := net.ParseCIDR(cidrString)
			if err != nil {
				return err
			}
			if len(ipNet.IP) != net.IPv4len {
				return fmt.Errorf("CIDR %s is not IPv4", cidrString)
			}
			cidrBitLength, _ := ipNet.Mask.Size()
			ipv4Addr := patricia.NewIPv4AddressFromBytes(ipNet.IP, uint(cidrBitLength))
			tags := tree.FindTags(ipv4Addr)
			if len(tags) == 1 {
				if tags[0] != regionId {
					return fmt.Errorf("CIDR %s in multiple regions", cidrString)
				}
				continue
			}
			_, _ = tree.Set(ipv4Addr, regionId)
		}
	}
	this.tree.Store(tree)
	return nil
}

// nolint:golint
func (this *aliyunIpToRegion) Lookup(ipString string) string {
	tree := this.tree.Load()
	if tree == nil {
		return ""
	}

	ip := net.ParseIP(ipString)
	if ip == nil {
		return ""
	}
	ip = ip.To4()
	if ip == nil {
		return ""
	}

	tags := tree.FindTags(patricia.NewIPv4AddressFromBytes(ip, 32))
	if len(tags) == 0 {
		return ""
	}
	return tags[0]
}
