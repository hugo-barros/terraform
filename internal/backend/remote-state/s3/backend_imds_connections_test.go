// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: BUSL-1.1

package s3

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/aws-sdk-go-base/v2/servicemocks"

	"github.com/hashicorp/terraform/internal/backend"
)

// fakeIMDS is a minimal IMDSv2 server that serves a static instance-profile
// credential and tracks how many client connections are currently open to it.
type fakeIMDS struct {
	*httptest.Server

	mu   sync.Mutex
	open map[net.Conn]struct{}

	tokenRequests      atomic.Int64
	credentialRequests atomic.Int64
}

func newFakeIMDS(t *testing.T) *fakeIMDS {
	t.Helper()

	f := &fakeIMDS{open: make(map[net.Conn]struct{})}

	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(f.serveHTTP))
	f.Server.Config.ConnState = func(c net.Conn, state http.ConnState) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch state {
		case http.StateNew:
			f.open[c] = struct{}{}
		case http.StateClosed, http.StateHijacked:
			delete(f.open, c)
		}
	}
	f.Server.Start()
	t.Cleanup(f.Server.Close)

	return f
}

// openConnections returns the number of client connections currently open.
func (f *fakeIMDS) openConnections() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.open)
}

func (f *fakeIMDS) serveHTTP(w http.ResponseWriter, r *http.Request) {
	const credentialsPath = "/latest/meta-data/iam/security-credentials/"

	switch {
	case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
		f.tokenRequests.Add(1)
		w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "21600")
		fmt.Fprint(w, "fake-imds-token")

	case r.Method == http.MethodGet && r.URL.Path == credentialsPath:
		fmt.Fprint(w, "fake-role")

	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, credentialsPath):
		f.credentialRequests.Add(1)
		fmt.Fprintf(w, `{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAFAKEIMDSKEY",
  "SecretAccessKey": "fake-secret",
  "Token": "fake-session-token",
  "Expiration": %q
}`, time.Now().UTC().Add(6*time.Hour).Format(time.RFC3339))

	default:
		http.NotFound(w, r)
	}
}

// Each `terraform_remote_state` data source using the S3 backend calls
// Configure() on its own Backend. Credentials come from the instance profile
// via IMDS, and every one of those Configure() calls used to build a separate
// credential chain with its own HTTP transport. Because the IMDS client keeps
// its connection alive, a configuration with N identical remote state data
// sources ended up holding ~N connections open to the metadata service.
//
// Some environments cap the number of concurrent connections a guest may hold
// to the metadata service (for example a sandboxed microVM runner), so the
// number of open connections must not grow with the number of backends.
func TestBackendConfig_IMDSConnectionsDoNotAccumulate(t *testing.T) {
	servicemocks.InitSessionTestEnv(t)

	imds := newFakeIMDS(t)

	const numBackends = 40

	for i := 0; i < numBackends; i++ {
		config := map[string]interface{}{
			"bucket":                        "tf-test",
			"key":                           fmt.Sprintf("state-%d", i),
			"region":                        "us-west-2",
			"ec2_metadata_service_endpoint": imds.URL,
			"skip_credentials_validation":   true,
			"skip_requesting_account_id":    true,
		}

		b := backend.TestBackendConfig(t, New(), backend.TestWrapConfig(config)).(*Backend)

		// Make sure the credentials really were sourced from the fake IMDS.
		creds, err := b.awsConfig.Credentials.Retrieve(t.Context())
		if err != nil {
			t.Fatalf("backend %d: retrieving credentials: %s", i, err)
		}
		if creds.AccessKeyID != "ASIAFAKEIMDSKEY" {
			t.Fatalf("backend %d: expected credentials from the fake IMDS, got access key %q (source %q)", i, creds.AccessKeyID, creds.Source)
		}
	}

	// Give the server a moment to observe any connections the clients closed.
	time.Sleep(100 * time.Millisecond)

	open := imds.openConnections()
	t.Logf("backends=%d open IMDS connections=%d token requests=%d credential requests=%d",
		numBackends, open, imds.tokenRequests.Load(), imds.credentialRequests.Load())

	const maxOpen = 2
	if open > maxOpen {
		t.Errorf("%d backends left %d connections open to the metadata service; expected at most %d (connections must not scale with the number of backends)",
			numBackends, open, maxOpen)
	}
}
