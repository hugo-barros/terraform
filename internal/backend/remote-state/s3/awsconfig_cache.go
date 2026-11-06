// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: BUSL-1.1

package s3

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsbase "github.com/hashicorp/aws-sdk-go-base/v2"
	basediag "github.com/hashicorp/aws-sdk-go-base/v2/diag"
)

// resolvedAwsConfigs is shared by every Backend in the process.
//
// Every `terraform_remote_state` data source that uses the S3 backend creates
// its own Backend and calls Configure on it. Resolving the AWS configuration
// builds a complete credential chain, including a dedicated HTTP transport,
// which is never closed. When the credentials come from the EC2 instance
// metadata service (IMDS) this leaves one keep-alive connection to the metadata
// service open per Backend, and re-fetches the very same credentials every time.
// A configuration with dozens of remote state data sources therefore holds
// dozens of connections to the metadata service.
//
// Backends whose resolved settings are identical can safely share a single
// aws.Config, and with it a single credential chain and connection pool.
var resolvedAwsConfigs = newAwsConfigCache()

// getAwsConfig returns the aws.Config for the given settings, resolving it with
// awsbase.GetAwsConfig only if an identical configuration has not already been
// resolved by this process.
func getAwsConfig(ctx context.Context, cfg *awsbase.Config) (aws.Config, basediag.Diagnostics) {
	return resolvedAwsConfigs.get(ctx, cfg, func(ctx context.Context, cfg *awsbase.Config) (aws.Config, basediag.Diagnostics) {
		_, awsConfig, diags := awsbase.GetAwsConfig(ctx, cfg)
		return awsConfig, diags
	})
}

type awsConfigResolver func(ctx context.Context, cfg *awsbase.Config) (aws.Config, basediag.Diagnostics)

type resolvedAwsConfig struct {
	awsConfig aws.Config
	diags     basediag.Diagnostics
}

// inflightAwsConfig is a resolution currently in progress. Concurrent callers
// asking for the same configuration wait for it rather than each starting their
// own, and share its result.
type inflightAwsConfig struct {
	resolvedAwsConfig
	done chan struct{}
}

type awsConfigCache struct {
	mu       sync.Mutex
	resolved map[string]resolvedAwsConfig
	inflight map[string]*inflightAwsConfig
}

func newAwsConfigCache() *awsConfigCache {
	return &awsConfigCache{
		resolved: make(map[string]resolvedAwsConfig),
		inflight: make(map[string]*inflightAwsConfig),
	}
}

func (c *awsConfigCache) get(ctx context.Context, cfg *awsbase.Config, resolve awsConfigResolver) (aws.Config, basediag.Diagnostics) {
	key, ok := awsConfigCacheKey(cfg)
	if !ok {
		// The settings cannot be compared reliably, so never share them.
		return resolve(ctx, cfg)
	}

	c.mu.Lock()
	if r, ok := c.resolved[key]; ok {
		c.mu.Unlock()
		return r.awsConfig, r.diags
	}
	if call, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		<-call.done
		return call.awsConfig, call.diags
	}
	call := &inflightAwsConfig{done: make(chan struct{})}
	c.inflight[key] = call
	c.mu.Unlock()

	call.awsConfig, call.diags = resolve(ctx, cfg)

	c.mu.Lock()
	delete(c.inflight, key)
	// Only successful resolutions are remembered, so that a failure (for
	// example the metadata service being briefly unavailable) is retried by the
	// next caller instead of being served for the life of the process.
	if !call.diags.HasError() {
		c.resolved[key] = call.resolvedAwsConfig
	}
	c.mu.Unlock()
	close(call.done)

	return call.awsConfig, call.diags
}

// awsConfigCacheKey returns a key identifying everything that influences how
// cfg is resolved, or false if cfg cannot be keyed reliably.
//
// The key is a hash of every field of cfg, plus the whole process environment,
// because AWS_* variables, proxy variables and the like are read directly by
// the AWS libraries and are not reflected in cfg. Any difference at all
// therefore results in a separate aws.Config.
func awsConfigCacheKey(cfg *awsbase.Config) (string, bool) {
	// These cannot be serialised. Terraform never sets them, but if that ever
	// changes the safe behaviour is to not share.
	if cfg.HTTPClient != nil || cfg.Backoff != nil {
		return "", false
	}

	keyed := *cfg
	// The logger only affects where log output goes, not how the configuration
	// is resolved, and differs for every Backend.
	keyed.Logger = nil

	serialized, err := json.Marshal(keyed)
	if err != nil {
		return "", false
	}

	env := os.Environ()
	sort.Strings(env)

	h := sha256.New()
	h.Write(serialized)
	h.Write([]byte{0})
	h.Write([]byte(strings.Join(env, "\x00")))

	return hex.EncodeToString(h.Sum(nil)), true
}
