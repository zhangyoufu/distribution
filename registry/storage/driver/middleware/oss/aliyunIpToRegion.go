package middleware

import (
	"cmp"
	"fmt"
	"log"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	vpc20160428 "github.com/alibabacloud-go/vpc-20160428/v6/client"
	credentials "github.com/aliyun/credentials-go/credentials"

	patricia "github.com/kentik/patricia"
	patricia_string_tree "github.com/kentik/patricia/string_tree"
)

// nolint:golint
type aliyunIpToRegion struct {
	regions []string
	tree    atomic.Pointer[patricia_string_tree.TreeV4]
}

// nolint:golint
func newAliyunIpToRegion(regions []string, refreshInterval time.Duration) (*aliyunIpToRegion, error) {
	this := &aliyunIpToRegion{
		regions: regions,
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

// comparePrefix returns an integer comparing two prefixes. The result will be
// 0 if lhs == rhs, -1 if lhs < rhs, and +1 if lhs > rhs. Prefixes sort first
// by validity (invalid before valid), then address family (IPv4 before IPv6),
// then masked prefix address, then prefix length, then unmasked address.
func comparePrefix(lhs, rhs netip.Prefix) int {
	// Aside from sorting based on the masked address, this use of Addr.Compare
	// also enforces the valid vs. invalid and address family ordering for the
	// prefix.
	if c := lhs.Masked().Addr().Compare(rhs.Masked().Addr()); c != 0 {
		return c
	}
	if c := cmp.Compare(lhs.Bits(), rhs.Bits()); c != 0 {
		return c
	}
	return lhs.Addr().Compare(rhs.Addr())
}

// nolint:golint
// prefix list should be sorted, to avoid adding multiple tags for overlapped prefixes
func (this *aliyunIpToRegion) fetchRegionPublicIPv4List(regionId string) ([]netip.Prefix, error) {
	config := &openapi.Config{}
	config.SetEndpoint("vpc.aliyuncs.com")

	cred, err := credentials.NewCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize aliyun credential: %w", err)
	}
	config.SetCredential(cred)

	client, err := vpc20160428.NewClient(config)
	if err != nil {
		return nil, err
	}

	request := &vpc20160428.DescribePublicIpAddressRequest{}
	request.SetRegionId(regionId)
	request.SetPageSize(math.MaxInt32)

	response, err := client.DescribePublicIpAddress(request)
	if err != nil {
		return nil, err
	}

	prefixList := []netip.Prefix{}
	for _, prefixStringPtr := range response.Body.PublicIpAddress {
		prefix, err := netip.ParsePrefix(*prefixStringPtr)
		if err != nil {
			log.Printf("aliyunIpToRegion.fetchRegionPublicIPv4List invalid prefix %s in region %s", *prefixStringPtr, regionId)
			continue
		}
		prefixList = append(prefixList, prefix)
	}
	slices.SortFunc(prefixList, comparePrefix)
	return prefixList, nil
}

// nolint:golint
func (this *aliyunIpToRegion) refresh() error {
	tree := patricia_string_tree.NewTreeV4()
	for _, regionId := range this.regions { // nolint:golint
		prefixList, err := this.fetchRegionPublicIPv4List(regionId)
		if err != nil {
			return fmt.Errorf("unable to fetch public IPv4 list for region %s: %w", regionId, err)
		}
		for _, prefix := range prefixList {
			addr := prefix.Addr().As4()
			_addr := patricia.NewIPv4AddressFromBytes(addr[:], uint(prefix.Bits()))
			tags := tree.FindTags(_addr)
			if len(tags) > 1 {
				if tags[0] != regionId {
					return fmt.Errorf("public IPv4 prefix %s in multiple regions", prefix)
				}
				continue
			}
			_, _ = tree.Set(_addr, regionId)
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
