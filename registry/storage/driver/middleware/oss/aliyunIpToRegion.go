package middleware

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	patricia "github.com/kentik/patricia"
	patricia_string_tree "github.com/kentik/patricia/string_tree"
)

func generateUrlSafeRandomToken(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf) // the error returned is not checked for simplicity
	return base64.RawURLEncoding.EncodeToString(buf)
}

func percentEncode(str string) string {
	return strings.Replace(url.QueryEscape(str), "+", "%20", -1)
}

func buildStringToSign(method string, path string, params url.Values) string {
	var qs string
	for _, key := range slices.Sorted(maps.Keys(params)) {
		// Note: multiple values under the same key are ignored, only the first value is used
		qs += "&" + percentEncode(key) + "=" + percentEncode(params.Get(key))
	}
	return percentEncode(method) + "&" + percentEncode(path) + "&" + percentEncode(qs[1:])
}

func sign(secret string, stringToSign string) string {
	h := hmac.New(sha1.New, []byte(secret+"&"))
	h.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type BaseResponse struct {
	Code      string
	Message   string
	RequestId string
}

type DescribePublicIpAddressResponse struct {
	BaseResponse
	RegionId        string
	PageSize        int
	PageNumber      int
	Success         bool
	TotalCount      int
	PublicIpAddress []string
}

// nolint:golint
type aliyunIpToRegion struct {
	accessKeyId     string
	accessKeySecret string
	refreshTimeout  time.Duration
	regions         []string
	tree            atomic.Pointer[patricia_string_tree.TreeV4]
}

// nolint:golint
func newAliyunIpToRegion(ctx context.Context, regions []string, refreshInterval, refreshTimeout time.Duration) (*aliyunIpToRegion, error) {
	accessKeyId, ok1 := os.LookupEnv("ALIBABA_CLOUD_ACCESS_KEY_ID")
	accessKeySecret, ok2 := os.LookupEnv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("aliyun credential not found")
	}
	this := &aliyunIpToRegion{
		accessKeyId:     accessKeyId,
		accessKeySecret: accessKeySecret,
		regions:         regions,
		refreshTimeout:  refreshTimeout,
	}
	err := this.refresh(ctx)
	if err != nil {
		return nil, err
	}
	go func() {
		ticker := time.NewTicker(refreshInterval)
		for {
			<-ticker.C
			err := this.refresh(context.Background())
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
// FIXME: aliyun official SDK does not support context
func (this *aliyunIpToRegion) fetchRegionPublicIPv4List(ctx context.Context, regionId string) ([]netip.Prefix, error) {
	params := url.Values{}

	// api parameters
	const endpoint = "https://vpc.aliyuncs.com"
	params.Set("Version", "2016-04-28")
	params.Set("Action", "DescribePublicIpAddress")
	const method = http.MethodGet
	params.Set("RegionId", regionId)
	params.Set("PageSize", "2147483647") // math.MaxInt32

	// common parameters
	const signatureVersion = "1.0"
	const signatureMethod = "HMAC-SHA1"
	params.Set("SignatureVersion", signatureVersion)
	params.Set("SignatureMethod", signatureMethod)
	params.Set("SignatureNonce", generateUrlSafeRandomToken(15))
	params.Set("Timestamp", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	params.Set("Format", "JSON")

	// signature
	params.Set("AccessKeyId", this.accessKeyId)
	stringToSign := buildStringToSign(method, "/", params)
	signature := sign(this.accessKeySecret, stringToSign)
	params.Set("Signature", signature)

	// send request
	requestUrl := endpoint + "/?" + params.Encode()
	httpReq, err := http.NewRequestWithContext(ctx, method, requestUrl, nil)
	if err != nil {
		return nil, err
	}

	// parse response
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()
	httpRespBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}
	var response DescribePublicIpAddressResponse
	err = json.Unmarshal(httpRespBody, &response)
	if err != nil {
		return nil, err
	}

	// pre-process CIDR list
	prefixList := []netip.Prefix{}
	for _, prefixString := range response.PublicIpAddress {
		prefix, err := netip.ParsePrefix(prefixString)
		if err != nil {
			log.Printf("aliyunIpToRegion.fetchRegionPublicIPv4List invalid prefix %s in region %s", prefixString, regionId)
			continue
		}
		prefixList = append(prefixList, prefix)
	}
	slices.SortFunc(prefixList, comparePrefix)
	return prefixList, nil
}

var errRefreshTimeout = errors.New("aliyunIpToRegion refresh timeout")

// nolint:golint
func (this *aliyunIpToRegion) refresh(ctx context.Context) error {
	if this.refreshTimeout > 0 {
		ctx, _ = context.WithTimeoutCause(ctx, this.refreshTimeout, errRefreshTimeout)
	}
	tree := patricia_string_tree.NewTreeV4()
	for _, regionId := range this.regions { // nolint:golint
		prefixList, err := this.fetchRegionPublicIPv4List(ctx, regionId)
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
