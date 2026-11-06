// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: BUSL-1.1

package s3

import (
	"context"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsbase "github.com/hashicorp/aws-sdk-go-base/v2"
	basediag "github.com/hashicorp/aws-sdk-go-base/v2/diag"
	"github.com/hashicorp/aws-sdk-go-base/v2/servicemocks"

	"github.com/hashicorp/terraform/internal/backend"
)

// countingResolver returns a resolver that records how many times it ran and
// tags each returned aws.Config with the call number via its Region, which
// lets tests tell resolutions apart.
func countingResolver(calls *atomic.Int64) awsConfigResolver {
	return func(ctx context.Context, cfg *awsbase.Config) (aws.Config, basediag.Diagnostics) {
		n := calls.Add(1)
		return aws.Config{Region: "resolution-" + string(rune('a'+n-1))}, nil
	}
}

func TestAwsConfigCache_IdenticalConfigsShareOneResolution(t *testing.T) {
	servicemocks.InitSessionTestEnv(t)

	var calls atomic.Int64
	cache := newAwsConfigCache()
	resolve := countingResolver(&calls)

	var first aws.Config
	for i := 0; i < 5; i++ {
		got, diags := cache.get(t.Context(), &awsbase.Config{Region: "us-west-2", Profile: "p"}, resolve)
		if diags.HasError() {
			t.Fatalf("unexpected errors: %v", diags)
		}
		if i == 0 {
			first = got
		} else if got.Region != first.Region {
			t.Fatalf("call %d returned a different configuration (%q) than the first (%q)", i, got.Region, first.Region)
		}
	}

	if n := calls.Load(); n != 1 {
		t.Fatalf("expected 1 resolution for 5 identical configurations, got %d", n)
	}
}

// Anything that can change how credentials are resolved must produce a
// separate aws.Config. These cases are the ones that would be security or
// correctness bugs if they were ever merged.
func TestAwsConfigCache_DifferentConfigsAreNotShared(t *testing.T) {
	servicemocks.InitSessionTestEnv(t)

	base := func() *awsbase.Config {
		return &awsbase.Config{
			Region:    "us-west-2",
			AccessKey: "AKIAEXAMPLE",
			SecretKey: "secret",
		}
	}

	cases := map[string]func(c *awsbase.Config){
		"region":      func(c *awsbase.Config) { c.Region = "eu-west-1" },
		"access key":  func(c *awsbase.Config) { c.AccessKey = "AKIAOTHER" },
		"secret key":  func(c *awsbase.Config) { c.SecretKey = "other-secret" },
		"session tok": func(c *awsbase.Config) { c.Token = "token" },
		"profile":     func(c *awsbase.Config) { c.Profile = "other" },
		"sts region":  func(c *awsbase.Config) { c.StsRegion = "us-east-1" },
		"sts endpoint": func(c *awsbase.Config) {
			c.StsEndpoint = "https://sts.example.test"
		},
		"imds endpoint": func(c *awsbase.Config) {
			c.EC2MetadataServiceEndpoint = "http://169.254.169.254"
		},
		"assume role": func(c *awsbase.Config) {
			c.AssumeRole = []awsbase.AssumeRole{{RoleARN: "arn:aws:iam::123456789012:role/r"}}
		},
		"assume role external id": func(c *awsbase.Config) {
			c.AssumeRole = []awsbase.AssumeRole{{RoleARN: "arn:aws:iam::123456789012:role/r", ExternalID: "x"}}
		},
		"web identity": func(c *awsbase.Config) {
			c.AssumeRoleWithWebIdentity = &awsbase.AssumeRoleWithWebIdentity{RoleARN: "arn:aws:iam::123456789012:role/r"}
		},
		"http proxy": func(c *awsbase.Config) {
			p := "http://proxy.test:3128"
			c.HTTPProxy = &p
		},
		"insecure":  func(c *awsbase.Config) { c.Insecure = true },
		"ca bundle": func(c *awsbase.Config) { c.CustomCABundle = "/tmp/ca.pem" },
		"allowed account ids": func(c *awsbase.Config) {
			c.AllowedAccountIds = []string{"123456789012"}
		},
		"max retries":  func(c *awsbase.Config) { c.MaxRetries = 9 },
		"fips":         func(c *awsbase.Config) { c.UseFIPSEndpoint = true },
		"skip creds":   func(c *awsbase.Config) { c.SkipCredsValidation = true },
		"shared files": func(c *awsbase.Config) { c.SharedCredentialsFiles = []string{"/tmp/creds"} },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			cache := newAwsConfigCache()
			resolve := countingResolver(&calls)

			cache.get(t.Context(), base(), resolve)

			changed := base()
			mutate(changed)
			cache.get(t.Context(), changed, resolve)

			if n := calls.Load(); n != 2 {
				t.Fatalf("changing %s must not reuse the cached configuration: expected 2 resolutions, got %d", name, n)
			}
		})
	}
}

func TestAwsConfigCache_EnvironmentChangeIsNotShared(t *testing.T) {
	servicemocks.InitSessionTestEnv(t)

	var calls atomic.Int64
	cache := newAwsConfigCache()
	resolve := countingResolver(&calls)
	cfg := func() *awsbase.Config { return &awsbase.Config{Region: "us-west-2"} }

	cache.get(t.Context(), cfg(), resolve)
	cache.get(t.Context(), cfg(), resolve)
	if n := calls.Load(); n != 1 {
		t.Fatalf("setup: expected 1 resolution, got %d", n)
	}

	// Environment variables are read directly by the AWS libraries rather than
	// through the config, so they must be part of the key.
	t.Setenv("AWS_PROFILE", "something-else")
	cache.get(t.Context(), cfg(), resolve)
	if n := calls.Load(); n != 2 {
		t.Fatalf("changing the environment must not reuse the cached configuration: expected 2 resolutions, got %d", n)
	}

	t.Setenv("HTTPS_PROXY", "http://proxy.test:3128")
	cache.get(t.Context(), cfg(), resolve)
	if n := calls.Load(); n != 3 {
		t.Fatalf("changing a proxy variable must not reuse the cached configuration: expected 3 resolutions, got %d", n)
	}
}

func TestAwsConfigCache_FailuresAreNotCached(t *testing.T) {
	servicemocks.InitSessionTestEnv(t)

	var calls atomic.Int64
	fail := true
	resolve := func(ctx context.Context, cfg *awsbase.Config) (aws.Config, basediag.Diagnostics) {
		calls.Add(1)
		if fail {
			return aws.Config{}, basediag.Diagnostics{}.AddError("no credentials", "metadata service unavailable")
		}
		return aws.Config{Region: "ok"}, nil
	}

	cache := newAwsConfigCache()
	cfg := func() *awsbase.Config { return &awsbase.Config{Region: "us-west-2"} }

	if _, diags := cache.get(t.Context(), cfg(), resolve); !diags.HasError() {
		t.Fatal("expected the first resolution to fail")
	}
	if _, diags := cache.get(t.Context(), cfg(), resolve); !diags.HasError() {
		t.Fatal("expected the second resolution to fail too, not to be served from a cache")
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("a failed resolution must be retried by the next caller: expected 2 resolutions, got %d", n)
	}

	// Once the underlying problem is fixed the next caller succeeds.
	fail = false
	got, diags := cache.get(t.Context(), cfg(), resolve)
	if diags.HasError() || got.Region != "ok" {
		t.Fatalf("expected recovery after the failure cleared, got region %q, diags %v", got.Region, diags)
	}
}

// Warnings produced while resolving a configuration are surfaced by every
// Configure call, exactly as they were before configurations were shared.
func TestAwsConfigCache_WarningsAreReplayed(t *testing.T) {
	servicemocks.InitSessionTestEnv(t)

	resolve := func(ctx context.Context, cfg *awsbase.Config) (aws.Config, basediag.Diagnostics) {
		return aws.Config{}, basediag.Diagnostics{}.AddWarning("deprecated thing", "stop doing it")
	}

	cache := newAwsConfigCache()
	for i := 0; i < 3; i++ {
		_, diags := cache.get(t.Context(), &awsbase.Config{Region: "us-west-2"}, resolve)
		if diags.WarningsCount() != 1 {
			t.Fatalf("call %d: expected the warning to be returned, got %v", i, diags)
		}
	}
}

// Many data sources are configured concurrently when Terraform walks the graph.
// Only one of them should do the work; the rest share its result.
func TestAwsConfigCache_ConcurrentCallersResolveOnce(t *testing.T) {
	servicemocks.InitSessionTestEnv(t)

	var calls atomic.Int64
	release := make(chan struct{})
	resolve := func(ctx context.Context, cfg *awsbase.Config) (aws.Config, basediag.Diagnostics) {
		calls.Add(1)
		<-release // hold the resolution open so the other callers pile up behind it
		return aws.Config{Region: "shared"}, nil
	}

	cache := newAwsConfigCache()
	const callers = 25

	var wg sync.WaitGroup
	results := make(chan string, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, _ := cache.get(t.Context(), &awsbase.Config{Region: "us-west-2"}, resolve)
			results <- got.Region
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)

	for region := range results {
		if region != "shared" {
			t.Fatalf("caller received %q, expected the shared resolution", region)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("expected exactly 1 resolution for %d concurrent callers, got %d", callers, n)
	}
}

func TestAwsConfigCache_UncacheableConfigsAreNeverShared(t *testing.T) {
	servicemocks.InitSessionTestEnv(t)

	cases := map[string]func(c *awsbase.Config){
		"custom http client": func(c *awsbase.Config) { c.HTTPClient = &http.Client{} },
		"custom backoff":     func(c *awsbase.Config) { c.Backoff = noBackoff{} },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			cache := newAwsConfigCache()
			resolve := countingResolver(&calls)

			for i := 0; i < 3; i++ {
				cfg := &awsbase.Config{Region: "us-west-2"}
				mutate(cfg)
				cache.get(t.Context(), cfg, resolve)
			}

			if n := calls.Load(); n != 3 {
				t.Fatalf("expected every call to resolve independently, got %d resolutions for 3 calls", n)
			}
		})
	}
}

type noBackoff struct{}

func (noBackoff) BackoffDelay(attempt int, err error) (time.Duration, error) { return 0, nil }

// The cache key is built by serialising awsbase.Config. If a newer
// aws-sdk-go-base adds a field the serialisation cannot see (an unexported
// field) or cannot represent (a func, chan or interface), configurations that
// differ only in that field would wrongly be treated as identical. Fail loudly
// so that whoever bumps the dependency has to decide how the new field is keyed.
func TestAwsConfigCacheKey_CoversEveryConfigField(t *testing.T) {
	handledExplicitly := map[string]bool{
		"Logger":     true, // excluded from the key on purpose
		"Backoff":    true, // makes the config uncacheable when set
		"HTTPClient": true, // makes the config uncacheable when set
	}

	rt := reflect.TypeOf(awsbase.Config{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if handledExplicitly[f.Name] {
			continue
		}
		if !f.IsExported() {
			t.Errorf("awsbase.Config.%s is unexported, so it is invisible to the cache key; handle it in awsConfigCacheKey", f.Name)
		}
		switch f.Type.Kind() {
		case reflect.Func, reflect.Chan, reflect.Interface, reflect.UnsafePointer:
			t.Errorf("awsbase.Config.%s has kind %s, which the cache key cannot represent; handle it in awsConfigCacheKey", f.Name, f.Type.Kind())
		}
	}
}

// The loggers differ for every Backend but do not affect resolution, so they
// must not defeat sharing.
func TestAwsConfigCacheKey_IgnoresLogger(t *testing.T) {
	servicemocks.InitSessionTestEnv(t)

	a := &awsbase.Config{Region: "us-west-2"}
	b := &awsbase.Config{Region: "us-west-2"}

	keyA, okA := awsConfigCacheKey(a)
	keyB, okB := awsConfigCacheKey(b)
	if !okA || !okB || keyA != keyB {
		t.Fatalf("identical configs must share a key (ok=%v/%v, %q vs %q)", okA, okB, keyA, keyB)
	}
}

// End to end through Configure: backends with different credentials must each
// get their own, and must never be handed another backend's.
func TestBackendConfig_DifferentCredentialsAreNotShared(t *testing.T) {
	servicemocks.InitSessionTestEnv(t)

	configure := func(accessKey string) *Backend {
		return backend.TestBackendConfig(t, New(), backend.TestWrapConfig(map[string]interface{}{
			"bucket":                      "tf-test",
			"key":                         "state",
			"region":                      "us-west-2",
			"access_key":                  accessKey,
			"secret_key":                  "secret-for-" + accessKey,
			"skip_credentials_validation": true,
			"skip_requesting_account_id":  true,
		})).(*Backend)
	}

	for _, accessKey := range []string{"AKIAFIRST", "AKIASECOND", "AKIAFIRST", "AKIATHIRD", "AKIASECOND"} {
		b := configure(accessKey)
		creds, err := b.awsConfig.Credentials.Retrieve(t.Context())
		if err != nil {
			t.Fatalf("retrieving credentials for %s: %s", accessKey, err)
		}
		if creds.AccessKeyID != accessKey {
			t.Fatalf("backend configured with %q was handed credentials for %q", accessKey, creds.AccessKeyID)
		}
		if creds.SecretAccessKey != "secret-for-"+accessKey {
			t.Fatalf("backend configured with %q was handed the wrong secret key", accessKey)
		}
	}
}
