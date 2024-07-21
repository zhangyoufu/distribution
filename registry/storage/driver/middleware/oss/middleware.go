package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	awsCredentials "github.com/aws/aws-sdk-go/aws/credentials"
	oss "github.com/aliyun/aliyun-oss-go-sdk/oss"
	dcontext "github.com/distribution/distribution/v3/internal/dcontext"
	requestutil "github.com/distribution/distribution/v3/internal/requestutil"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	storagemiddleware "github.com/distribution/distribution/v3/registry/storage/driver/middleware"
)

type ossStorageMiddleware struct {
	storagedriver.StorageDriver
	urlExpiration time.Duration
	buckets       map[string]*oss.Bucket
	ipToRegion    *aliyunIpToRegion
}

var _ storagedriver.StorageDriver = &ossStorageMiddleware{}

type CredentialProvider interface {
	Credential() (awsCredentials.Value, error)
}

func newOssStorageMiddleware(ctx context.Context, storageDriver storagedriver.StorageDriver, options map[string]interface{}) (storagedriver.StorageDriver, error) {
	// retrieve S3 credential from underlying storage driver
	credentialProvider, ok := storageDriver.(CredentialProvider)
	if !ok {
		return nil, fmt.Errorf("the underlying storage driver does not provide credential")
	}
	credential, err := credentialProvider.Credential()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve credential from underlying storage driver")
	}

	// parse secure
	secure := true
	if _secure, ok := options["secure"]; ok {
		if secure, ok = _secure.(bool); !ok {
			return nil, fmt.Errorf("secure must be a bool")
		}
	}

	// parse urlExpiration
	urlExpiration := 20 * time.Minute
	if d, ok := options["urlExpiration"]; ok {
		switch d := d.(type) {
		case time.Duration:
			urlExpiration = d
		case string:
			dur, err := time.ParseDuration(d)
			if err != nil {
				return nil, fmt.Errorf("invalid urlExpiration: %w", err)
			}
			urlExpiration = dur
		default:
			return nil, fmt.Errorf("invalid urlExpiration: unsupported type")
		}
		// the largest representable time.Duration is approximately 290 years
		// which is far less than (2**63-1)-seconds_since_unix_epoch
		// so we don't have to check the upper bound here
		if urlExpiration <= 0 {
			return nil, fmt.Errorf("invalid urlExpiration: should be positive")
		}
	}

	// parse regionIpRefreshInterval
	regionIpRefreshInterval := 4 * time.Hour // nolint:golint
	if d, ok := options["regionIpRefreshInterval"]; ok {
		switch d := d.(type) {
		case time.Duration:
			regionIpRefreshInterval = d
		case string:
			dur, err := time.ParseDuration(d)
			if err != nil {
				return nil, fmt.Errorf("invalid regionIpRefreshInterval: %w", err)
			}
			regionIpRefreshInterval = dur
		default:
			return nil, fmt.Errorf("invalid regionIpRefreshInterval: unsupported type")
		}
		if regionIpRefreshInterval <= 0 {
			return nil, fmt.Errorf("invalid regionIpRefreshInterval: should be positive")
		}
	}

	// parse regionIpRefreshTimeout
	regionIpRefreshTimeout := time.Duration(0) // nolint:golint
	if d, ok := options["regionIpRefreshTimeout"]; ok {
		switch d := d.(type) {
		case time.Duration:
			regionIpRefreshTimeout = d
		case string:
			dur, err := time.ParseDuration(d)
			if err != nil {
				return nil, fmt.Errorf("invalid regionIpRefreshTimeout: %w", err)
			}
			regionIpRefreshTimeout = dur
		default:
			return nil, fmt.Errorf("invalid regionIpRefreshTimeout: unsupported type")
		}
		if regionIpRefreshTimeout < 0 {
			return nil, fmt.Errorf("invalid regionIpRefreshTimeout: should be non-negative")
		}
	}

	// parse buckets
	_buckets, ok := options["buckets"]
	if !ok {
		return nil, fmt.Errorf("buckets is not provided")
	}
	_bucketsMap, ok := _buckets.(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("buckets were not specified in the correct format")
	}
	buckets := map[string]*oss.Bucket{}
	regions := []string{}
	for _regionId, _bucketName := range _bucketsMap { // nolint:golint
		regionId, ok := _regionId.(string) // nolint:golint
		if !ok {
			return nil, fmt.Errorf("bucket regionId was not a string")
		}
		regions = append(regions, regionId)
		bucketName, ok := _bucketName.(string)
		if !ok {
			return nil, fmt.Errorf("bucket name was not a string")
		}
		scheme := "http://"
		if secure {
			scheme = "https://"
		}
		endpoint := scheme + "oss-" + regionId + "-internal.aliyuncs.com"
		client, err := oss.New(endpoint, credential.AccessKeyID, credential.SecretAccessKey,
			oss.AuthVersion(oss.AuthV4),
			oss.Region(regionId),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to instantiate OSS client: %w", err)
		}
		bucket, err := client.Bucket(bucketName)
		if err != nil {
			return nil, fmt.Errorf("unable to instantiate OSS bucket: %w", err)
		}
		buckets[regionId] = bucket
	}

	// initialize ipToRegion
	ipToRegion, err := newAliyunIpToRegion(ctx, regions, regionIpRefreshInterval, regionIpRefreshTimeout)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize aliyunIpToRegion: %w", err)
	}

	return &ossStorageMiddleware{
		StorageDriver: storageDriver,
		urlExpiration: urlExpiration,
		buckets:       buckets,
		ipToRegion:    ipToRegion,
	}, nil
}

func (lh *ossStorageMiddleware) RedirectURL(r *http.Request, urlPath string) (string, error) {
	if r.Method != http.MethodGet {
		return lh.StorageDriver.RedirectURL(r, urlPath)
	}

	ipString := requestutil.RemoteIP(r)        // according to X-Forwarded-For or X-Real-Ip header
	regionId := lh.ipToRegion.Lookup(ipString) // nolint:golint
	if regionId == "" {
		return lh.StorageDriver.RedirectURL(r, urlPath)
	}
	dcontext.GetLogger(r.Context()).Debugf("ip %s => aliyun region %s", ipString, regionId)

	bucket, ok := lh.buckets[regionId]
	if !ok {
		return lh.StorageDriver.RedirectURL(r, urlPath)
	}

	objectKey := strings.TrimLeft(urlPath, "/")
	return bucket.SignURL(objectKey, oss.HTTPMethod(r.Method), lh.urlExpiration.Milliseconds()/1000)
}

func init() {
	storagemiddleware.Register("oss", storagemiddleware.InitFunc(newOssStorageMiddleware))
}
