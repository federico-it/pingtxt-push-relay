package server

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestOpenAPIRoutes checks that every operation in docs/openapi.json (the
// schema uploaded to Cloudflare) is a route the relay serves, and that every
// route is documented: a missing route would be blocked at the edge.
func TestOpenAPIRoutes(t *testing.T) {
	raw, err := os.ReadFile("../../docs/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		OpenAPI string                    `json:"openapi"`
		Paths   map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.0.") {
		t.Fatalf("openapi %q: Cloudflare takes 3.0.x", doc.OpenAPI)
	}
	documented := map[string]bool{}
	e := setup(t, nil)
	for path, ops := range doc.Paths {
		for method := range ops {
			m := strings.ToUpper(method)
			documented[m+" "+path] = true
			req, _ := http.NewRequest(m, e.srv.URL+path, strings.NewReader("{}"))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
				t.Errorf("%s %s is documented but not served (%d)", m, path, resp.StatusCode)
			}
		}
	}
	// Keep in sync with Handler.
	for _, r := range []string{"GET /", "GET /healthz", "POST /v1/hubs", "GET /v1/hubs/me",
		"POST /v1/devices", "POST /v1/push", "POST /v1/live-activity"} {
		if !documented[r] {
			t.Errorf("%s is served but missing from docs/openapi.json", r)
		}
	}
}
