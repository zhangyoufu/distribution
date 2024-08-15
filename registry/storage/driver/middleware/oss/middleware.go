package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	dcontext "github.com/distribution/distribution/v3/internal/dcontext"
	requestutil "github.com/distribution/distribution/v3/internal/requestutil"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	storagemiddleware "github.com/distribution/distribution/v3/registry/storage/driver/middleware"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

type bucket struct {
	s3   *s3.S3
	name string
}

type ossStorageMiddleware struct {
	storagedriver.StorageDriver
	urlExpiration time.Duration
	buckets       map[string]bucket
	ipToRegion    *aliyunIpToRegion
}

var _ storagedriver.StorageDriver = &ossStorageMiddleware{}

type CredentialsProvider interface {
	Credentials() *credentials.Credentials
}

func newOssStorageMiddleware(ctx context.Context, storageDriver storagedriver.StorageDriver, options map[string]interface{}) (storagedriver.StorageDriver, error) {
	// retrieve S3 credentials from underlying storage driver
	credentialsProvider, ok := storageDriver.(CredentialsProvider)
	if !ok {
		return nil, fmt.Errorf("the underlying storage driver did not implement CredentialsProvider interface")
	}
	creds := credentialsProvider.Credentials()

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
	buckets := map[string]bucket{}
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
		awsConfig := aws.NewConfig()
		awsConfig.WithCredentials(creds)
		awsConfig.WithRegion(regionId)
		awsConfig.WithEndpoint("oss-" + regionId + "-internal.aliyuncs.com")
		awsConfig.WithDisableSSL(!secure)
		sess, err := session.NewSession(awsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create aws session: %v", err)
		}
		buckets[regionId] = bucket{
			s3:   s3.New(sess),
			name: bucketName,
		}
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

func s3Path(path string) string {
	return strings.TrimLeft(path, "/")
}

func (lh *ossStorageMiddleware) RedirectURL(r *http.Request, path string) (string, error) {
	if r.Method != http.MethodGet {
		// blobserver.ServeBlob will fallback to serving the content directly
		return "", nil
	}

	ipString := requestutil.RemoteIP(r)        // according to X-Forwarded-For or X-Real-Ip header
	regionId := lh.ipToRegion.Lookup(ipString) // nolint:golint
	if regionId == "" {
		return lh.StorageDriver.RedirectURL(r, path)
	}
	dcontext.GetLogger(r.Context()).Debugf("ip %s => aliyun region %s", ipString, regionId)

	bucket, ok := lh.buckets[regionId]
	if !ok {
		return lh.StorageDriver.RedirectURL(r, path)
	}

	req, _ := bucket.s3.GetObjectRequest(&s3.GetObjectInput{
		Bucket: aws.String(bucket.name),
		Key:    aws.String(s3Path(path)),
	})
	return req.Presign(lh.urlExpiration)
}

func init() {
	storagemiddleware.Register("oss", storagemiddleware.InitFunc(newOssStorageMiddleware))
}
