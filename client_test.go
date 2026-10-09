package ipscanner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, h http.HandlerFunc, opts ...Option) *Client {
	t.Helper()
	t.Setenv("IPSCANNER_API_KEY", "")
	t.Setenv("IPSCANNER_API_URL", "")
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := NewClient(append([]Option{WithBaseURL(srv.URL), WithAPIKey("pk_test_123")}, opts...)...)
	c.backoff = func(int) time.Duration { return 0 }
	return c
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func TestAuthHeaderPresent(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer pk_test_123" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "ipscanner-go/0.2.0" {
			t.Errorf("User-Agent = %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
		}
		writeJSON(w, 200, map[string]any{"ip": "8.8.8.8", "isVpn": false})
	})
	if _, err := c.IP.VPN(context.Background(), "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
}

func TestAuthHeaderAbsentWithoutKey(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; ok {
			t.Errorf("unexpected Authorization header")
		}
		writeJSON(w, 200, map[string]any{"country": "US", "ipv4": "1.2.3.4"})
	}, WithAPIKey(""))
	me, err := c.IP.MyIP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if me.IPv4 != "1.2.3.4" {
		t.Errorf("IPv4 = %q", me.IPv4)
	}
}

func TestEnvFallback(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		writeJSON(w, 200, map[string]any{})
	}))
	defer srv.Close()
	t.Setenv("IPSCANNER_API_KEY", "env-key")
	t.Setenv("IPSCANNER_API_URL", srv.URL+"/")
	c := NewClient()
	if _, err := c.Account.Limits(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer env-key" {
		t.Errorf("Authorization = %q", gotAuth)
	}
}

func TestDefaultBaseURL(t *testing.T) {
	t.Setenv("IPSCANNER_API_URL", "")
	if c := NewClient(); c.baseURL != DefaultBaseURL {
		t.Errorf("baseURL = %q", c.baseURL)
	}
}

func TestPathEscapingIPv6(t *testing.T) {
	cases := []struct {
		name string
		call func(c *Client) error
		want string
	}{
		{"vpn", func(c *Client) error { _, err := c.IP.VPN(context.Background(), "2001:db8::1"); return err }, "/v1/vpn/2001%3Adb8%3A%3A1"},
		{"proxy", func(c *Client) error { _, err := c.IP.Proxy(context.Background(), "2001:db8::1"); return err }, "/v1/proxy/2001%3Adb8%3A%3A1"},
		{"geo", func(c *Client) error { _, err := c.IP.Geo(context.Background(), "::1"); return err }, "/v1/geo/%3A%3A1"},
		{"asn", func(c *Client) error { _, err := c.IP.ASN(context.Background(), "fe80::1"); return err }, "/v1/asn/fe80%3A%3A1"},
		{"demo", func(c *Client) error { _, err := c.IP.Demo(context.Background(), "2001:db8::1"); return err }, "/v1/demo/2001%3Adb8%3A%3A1"},
		{"whois", func(c *Client) error { _, err := c.IP.Whois(context.Background(), "a b/c"); return err }, "/v1/whois/a%20b%2Fc"},
		{"asn directory", func(c *Client) error { _, err := c.ASNDirectory.Get(context.Background(), "AS15169"); return err }, "/v1/asn/directory/15169"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI != tc.want {
					t.Errorf("RequestURI = %q, want %q", r.RequestURI, tc.want)
				}
				writeJSON(w, 200, map[string]any{})
			})
			if err := tc.call(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLookup(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/ip/lookup" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"target":"1.1.1.1"}` {
			t.Errorf("body = %s", body)
		}
		io.WriteString(w, `{
			"target": {"raw": "1.1.1.1", "kind": "ipv4", "ip": "1.1.1.1"},
			"reserved": {"reserved": false},
			"verdict": {"classification": "hosting", "anonymized": false, "confidence": 0.92, "method": "asn"},
			"purity": {"score": 70, "grade": "B", "verdict": "suspect", "deductions": [{"factor": "hosting", "points": 30, "detail": "x"}]},
			"networkClass": "hosting", "isVpn": false, "isProxy": false, "isTor": false, "riskScore": 30,
			"asn": {"ip": "1.1.1.1", "asn": "AS13335", "name": "Cloudflare", "type": "hosting", "country": "US"},
			"at": "2026-10-06T12:00:00.123456789Z"
		}`)
	})
	res, err := c.IP.Lookup(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict.Classification != "hosting" || res.Purity.Deductions[0].Points != 30 || res.ASN.ASN != "AS13335" {
		t.Errorf("unexpected result: %+v", res)
	}
	if res.Geo != nil {
		t.Errorf("Geo should be nil")
	}
	if res.At.Nanosecond() != 123456789 {
		t.Errorf("At = %v", res.At)
	}
}

func TestHistoryQuery(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.RawQuery; got != "before=42&limit=10&verdict=dirty" {
			t.Errorf("query = %q", got)
		}
		writeJSON(w, 200, map[string]any{"events": []any{map[string]any{"id": 41, "ip": "1.2.3.4"}}, "nextBefore": 0})
	})
	h, err := c.IP.History(context.Background(), &HistoryParams{Limit: 10, Before: 42, Verdict: "dirty"})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Events) != 1 || h.Events[0].ID != 41 || h.NextBefore != 0 {
		t.Errorf("unexpected history: %+v", h)
	}
}

func TestSnakeCaseBodies(t *testing.T) {
	cases := []struct {
		name string
		path string
		call func(c *Client) error
		want string
	}{
		{
			"agentscan check", "/v1/agentscan/check",
			func(c *Client) error {
				_, err := c.Agentscan.Check(context.Background(), AgentscanCheckParams{
					IP: "1.2.3.4", UserAgent: "curl/8", JA4: "t13d", RequestID: "r1",
					Headers: map[string]string{"accept": "*/*"}, HeadlessFlags: map[string]bool{"webdriver": true},
				})
				return err
			},
			`{"ip":"1.2.3.4","user_agent":"curl/8","ja4":"t13d","headers":{"accept":"*/*"},"headless_flags":{"webdriver":true},"request_id":"r1"}`,
		},
		{
			"agentscan check minimal", "/v1/agentscan/check",
			func(c *Client) error {
				_, err := c.Agentscan.Check(context.Background(), AgentscanCheckParams{IP: "1.2.3.4"})
				return err
			},
			`{"ip":"1.2.3.4"}`,
		},
		{
			"agentscan batch", "/v1/agentscan/batch",
			func(c *Client) error {
				_, err := c.Agentscan.Batch(context.Background(), []AgentscanBatchLine{{Line: 1, IP: "1.2.3.4", UserAgent: "GPTBot"}})
				return err
			},
			`{"lines":[{"line":1,"ip":"1.2.3.4","user_agent":"GPTBot"}]}`,
		},
		{
			"agentscan verify", "/v1/agentscan/verify",
			func(c *Client) error {
				_, err := c.Agentscan.Verify(context.Background(), AgentscanVerifyParams{IP: "66.249.66.1", UserAgent: "Googlebot"})
				return err
			},
			`{"ip":"66.249.66.1","user_agent":"Googlebot"}`,
		},
		{
			"agentscan self empty", "/v1/agentscan/self",
			func(c *Client) error {
				_, err := c.Agentscan.SelfCheck(context.Background(), nil)
				return err
			},
			`{}`,
		},
		{
			"provenance check", "/v1/provenance/check",
			func(c *Client) error {
				_, err := c.Provenance.Check(context.Background(), ProvenanceCheckParams{
					IP: "1.2.3.4", ClaimedJurisdiction: "uk", RequestContext: map[string]any{"path": "/"},
				})
				return err
			},
			`{"ip":"1.2.3.4","claimed_jurisdiction":"uk","request_context":{"path":"/"}}`,
		},
		{
			"provenance verify anchored", "/v1/provenance/verify",
			func(c *Client) error {
				_, err := c.Provenance.VerifyAnchored(context.Background())
				return err
			},
			`{}`,
		},
		{
			"bulk check", "/v1/bulk/check",
			func(c *Client) error {
				_, err := c.Bulk.Check(context.Background(), BulkParams{Input: "1.1.1.1\n8.8.8.8"})
				return err
			},
			`{"input":"1.1.1.1\n8.8.8.8"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != tc.path {
					t.Errorf("%s %s", r.Method, r.URL.Path)
				}
				if ct := r.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type = %q", ct)
				}
				body, _ := io.ReadAll(r.Body)
				if string(body) != tc.want {
					t.Errorf("body = %s\nwant   %s", body, tc.want)
				}
				writeJSON(w, 200, map[string]any{})
			})
			if err := tc.call(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProvenanceCheckResponse(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"network_origin":"residential_clean","anonymized":false,"method":"asn","confidence":0.9,"policy_action":"allow","attestation_id":77}`)
	})
	res, err := c.Provenance.Check(context.Background(), ProvenanceCheckParams{IP: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if res.NetworkOrigin != "residential_clean" || res.PolicyAction != "allow" || res.AttestationID != 77 {
		t.Errorf("unexpected result: %+v", res)
	}
}

func TestProvenanceChain(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.RawQuery; got != "before=9&limit=5" {
			t.Errorf("query = %q", got)
		}
		io.WriteString(w, `{"links":[{"id":8,"ts":"2026-10-01T00:00:00Z","entryOk":true,"linkOk":true}],"nextBefore":8,"total":20,
			"summary":{"allow":10,"step_up":7,"block":3},"anchor":null,"jurisdictions":[{"code":"uk","strict":true}],"asOf":"2026-10-06T00:00:00Z"}`)
	})
	page, err := c.Provenance.Chain(context.Background(), &ChainParams{Limit: 5, Before: 9})
	if err != nil {
		t.Fatal(err)
	}
	if page.Summary.StepUp != 7 || page.Anchor != nil || !page.Links[0].LinkOK || page.Jurisdictions[0].Code != "uk" {
		t.Errorf("unexpected page: %+v", page)
	}
}

func TestProvenanceExport(t *testing.T) {
	csv := "# provenance evidence export\nid,ts,ip\n1,2026-10-01T00:00:00Z,1.2.3.4\n"
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/provenance/export" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.URL.RawQuery; got != "from=2026-10-01&to=2026-10-06" {
			t.Errorf("query = %q", got)
		}
		if got := r.Header.Get("Accept"); got != "text/csv" {
			t.Errorf("Accept = %q", got)
		}
		w.Header().Set("Content-Type", "text/csv")
		io.WriteString(w, csv)
	})
	got, err := c.Provenance.Export(context.Background(), &ExportParams{From: "2026-10-01", To: "2026-10-06"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != csv {
		t.Errorf("csv = %q", got)
	}
}

func TestASNDirectory(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/asn/directory/15169":
			io.WriteString(w, `{"asn":15169,"label":"AS15169","org":"GOOGLE","addresses":8000000,"samplePrefixes":[{"prefix":"8.8.8.0/24","version":4,"addresses":256}],"rangesLoaded":true}`)
		case "/v1/asn/directory":
			if q := r.URL.Query().Get("q"); q != "" {
				if q != "google" || r.URL.Query().Get("limit") != "5" {
					t.Errorf("query = %q", r.URL.RawQuery)
				}
				io.WriteString(w, `{"total":80000,"query":"google","count":1,"results":[{"asn":15169}]}`)
				return
			}
			if r.URL.RawQuery != "by=prefixes&top=3" {
				t.Errorf("query = %q", r.URL.RawQuery)
			}
			io.WriteString(w, `{"total":80000,"by":"prefixes","count":1,"results":[{"asn":3356}]}`)
		}
	})
	ctx := context.Background()
	d, err := c.ASNDirectory.Get(ctx, "as15169")
	if err != nil {
		t.Fatal(err)
	}
	if d.ASN != 15169 || d.Org != "GOOGLE" || d.SamplePrefixes[0].Addresses != 256 || !d.RangesLoaded {
		t.Errorf("unexpected detail: %+v", d)
	}
	s, err := c.ASNDirectory.Search(ctx, "google", &ASNSearchParams{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if s.Query != "google" || s.Results[0].ASN != 15169 {
		t.Errorf("unexpected search: %+v", s)
	}
	top, err := c.ASNDirectory.Top(ctx, &ASNTopParams{Top: 3, By: "prefixes"})
	if err != nil {
		t.Fatal(err)
	}
	if top.By != "prefixes" || top.Results[0].ASN != 3356 {
		t.Errorf("unexpected top: %+v", top)
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		code     string
		message  string
		notFound bool
		auth     bool
	}{
		{"not found", 404, `{"error":"not_found","message":"No such ASN"}`, "not_found", "No such ASN", true, false},
		{"unauthorized", 401, `{"error":"invalid_api_key","message":"Invalid API key"}`, "invalid_api_key", "Invalid API key", false, true},
		{"suspended", 403, `{"error":"account_suspended","message":"Suspended"}`, "account_suspended", "Suspended", false, true},
		{"bad request", 400, `{"error":"invalid_ip","message":"Invalid IP address format"}`, "invalid_ip", "Invalid IP address format", false, false},
		{"non-json", 500, `<html>oops</html>`, "http_500", "Internal Server Error", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			_, err := c.IP.Lookup(context.Background(), "x")
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %v", err)
			}
			if apiErr.Status != tc.status || apiErr.Code != tc.code || apiErr.Message != tc.message || string(apiErr.Body) != tc.body {
				t.Errorf("unexpected error: %+v", apiErr)
			}
			if IsNotFound(err) != tc.notFound || IsAuth(err) != tc.auth || IsRateLimited(err) {
				t.Errorf("helpers mismatch for %v", err)
			}
		})
	}
}

func TestBulkInvalidDetails(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 400, map[string]any{"error": "bad_request", "message": "No valid IP addresses found", "details": map[string]any{"invalid": []string{"nope", "999.1.1.1"}}})
	})
	_, err := c.Bulk.Check(context.Background(), BulkParams{IPs: []string{"nope", "999.1.1.1"}})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v", err)
	}
	if inv := apiErr.Invalid(); len(inv) != 2 || inv[1] != "999.1.1.1" {
		t.Errorf("Invalid() = %v", inv)
	}
}

func TestRateLimitQuotaBody(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "999")
		w.Header().Set("X-RateLimit-Meter", "request")
		w.Header().Set("X-RateLimit-Limit", "30000")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "1793491200")
		w.Header().Set("X-Quota-Upgrade-Url", "https://ipscanner.io/header")
		writeJSON(w, 429, map[string]any{
			"error": "rate_limit_exceeded", "reason": "insufficient_for_batch", "message": "This batch needs 500 requests",
			"meter": "request", "plan": "Free", "limit": 30000, "usage": 29600, "remaining": 400, "needed": 500,
			"resetDate": "2026-11-01", "resetAt": "2026-11-01T00:00:00Z", "retryAfter": 120, "softBlock": false,
			"upgrade": map[string]any{"recommendedPlan": "Starter", "url": "https://ipscanner.io/pricing", "message": "Upgrade"},
		})
	})
	_, err := c.Bulk.Check(context.Background(), BulkParams{IPs: []string{"1.1.1.1"}})
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v", err)
	}
	if rl.Reason != "insufficient_for_batch" || rl.Remaining != 400 || rl.Needed != 500 || rl.Limit != 30000 || rl.Usage != 29600 || rl.Plan != "Free" {
		t.Errorf("unexpected fields: %+v", rl)
	}
	if rl.RetryAfter != 120*time.Second {
		t.Errorf("RetryAfter = %v, want body value", rl.RetryAfter)
	}
	if !rl.ResetAt.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) || rl.ResetDate != "2026-11-01" {
		t.Errorf("ResetAt = %v ResetDate = %q", rl.ResetAt, rl.ResetDate)
	}
	if rl.UpgradeURL != "https://ipscanner.io/pricing" || rl.RecommendedPlan != "Starter" {
		t.Errorf("upgrade = %q %q", rl.UpgradeURL, rl.RecommendedPlan)
	}
	if rl.RateLimit.Limit != 30000 || rl.RateLimit.Meter != "request" || rl.RateLimit.Reset.Unix() != 1793491200 || rl.RateLimit.RetryAfter != 999*time.Second {
		t.Errorf("headers = %+v", rl.RateLimit)
	}
	if rl.Code != "rate_limit_exceeded" || rl.Status != 429 || !IsRateLimited(err) {
		t.Errorf("base error = %+v", rl.APIError)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 429 {
		t.Errorf("errors.As *APIError failed")
	}
}

func TestRateLimitRetryAfterHeaderFallback(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		writeJSON(w, 429, map[string]any{"error": "rate_limit_exceeded", "message": "Too many requests"})
	})
	_, err := c.IP.Demo(context.Background(), "1.1.1.1")
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v", err)
	}
	if rl.RetryAfter != 30*time.Second {
		t.Errorf("RetryAfter = %v", rl.RetryAfter)
	}
}

func TestRateLimitKeylessBody(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 429, map[string]any{"error": "rate_limit_exceeded", "message": "Too many requests from this IP.", "retryAfter": 0})
	})
	_, err := c.IP.MyIP(context.Background())
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v", err)
	}
	if rl.RetryAfter != 0 || rl.Reason != "" {
		t.Errorf("unexpected: %+v", rl)
	}
}

func TestGetRetriesOn503(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		writeJSON(w, 200, map[string]any{"ip": "1.1.1.1", "country": "AU"})
	})
	geo, err := c.IP.Geo(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if geo.Country != "AU" || calls.Load() != 2 {
		t.Errorf("country = %q calls = %d", geo.Country, calls.Load())
	}
}

func TestGetRetriesExhausted(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(502)
	})
	_, err := c.IP.Geo(context.Background(), "1.1.1.1")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "http_502" {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("calls = %d, want 3", calls.Load())
	}
}

func TestGetRetriesOnNetworkError(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		writeJSON(w, 200, map[string]any{"crawlers": []any{}, "count": 0})
	})
	if _, err := c.Crawlers.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d", calls.Load())
	}
}

func TestNoRetryOnPostOr429(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		call   func(c *Client) error
	}{
		{"post 503", 503, func(c *Client) error { _, err := c.IP.Lookup(context.Background(), "1.1.1.1"); return err }},
		{"get 429", 429, func(c *Client) error { _, err := c.Account.Usage(context.Background()); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
			})
			if err := tc.call(c); err == nil {
				t.Fatal("expected error")
			}
			if calls.Load() != 1 {
				t.Errorf("calls = %d, want 1", calls.Load())
			}
		})
	}
}

func TestTimeout(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}, WithTimeout(50*time.Millisecond), WithMaxRetries(0))
	_, err := c.Account.Limits(context.Background())
	var connErr *ConnectionError
	if !errors.As(err, &connErr) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestAccountLimitsNullWindows(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"accountType":"Pro","limit":500000,"usage":10,"remaining":499990,"resetDate":"2026-11-01","daily":null,
			"hourly":{"limit":5000,"used":3,"remaining":4997,"resetAt":"2026-10-06T13:00:00Z"}}`)
	})
	l, err := c.Account.Limits(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if l.Daily != nil || l.Hourly == nil || l.Hourly.Remaining != 4997 {
		t.Errorf("unexpected limits: %+v", l)
	}
}

func TestLookupLocked(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{
			"target": {"raw": "example.com", "kind": "hostname", "ip": "93.184.216.34", "hostname": "example.com"},
			"reserved": {"reserved": false},
			"verdict": {"classification": "vpn", "anonymized": true, "confidence": 0.9, "method": "range", "evidence": ["vpn_range", "future_value"]},
			"purity": null, "provider": null, "vpnProvider": null,
			"networkClass": "some_new_class", "isVpn": true, "isProxy": false, "isTor": false, "riskScore": 80,
			"geo": {"ip": "93.184.216.34", "country": "United States", "countryCode": "US", "city": "", "region": "",
				"postalCode": null, "latitude": null, "longitude": null, "timezone": "UTC", "accuracyRadius": null},
			"whoisStatus": "timeout", "degraded": ["whois"],
			"at": "2026-10-09T12:00:00Z",
			"locked": ["purity", "provider", "vpnProvider", "geo.latitude", "geo.longitude", "geo.postalCode", "geo.accuracyRadius"],
			"planRequired": "Starter"
		}`)
	})
	res, err := c.IP.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Purity.Score != 0 || res.Purity.Deductions != nil || res.Provider != "" || res.VPNProvider != "" {
		t.Errorf("premium fields not zero: %+v", res)
	}
	if res.Geo.Latitude != 0 || res.Geo.PostalCode != "" || res.Geo.AccuracyRadius != 0 || res.Geo.CountryCode != "US" {
		t.Errorf("geo = %+v", res.Geo)
	}
	if len(res.Locked) != 7 || res.Locked[3] != "geo.latitude" || res.PlanRequired != "Starter" {
		t.Errorf("markers = %v %q", res.Locked, res.PlanRequired)
	}
	if res.NetworkClass != "some_new_class" || len(res.Verdict.Evidence) != 2 {
		t.Errorf("unexpected result: %+v", res)
	}
	if res.Whois != nil || res.WhoisStatus != "timeout" {
		t.Errorf("whois = %+v status %q", res.Whois, res.WhoisStatus)
	}
}

func TestLookupVPNProvider(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{
			"target": {"raw": "example.com", "kind": "hostname", "ip": "185.65.134.1", "hostname": "example.com"},
			"verdict": {"classification": "vpn", "anonymized": true, "confidence": 0.99, "method": "list", "evidence": ["vpn_server_list"]},
			"purity": {"score": 10, "grade": "C", "verdict": "dirty", "deductions": []},
			"networkClass": "vpn", "isVpn": true, "provider": "M247", "vpnProvider": "Mullvad", "riskScore": 95,
			"whois": {"domain": "example.com", "registrar": "R", "nameservers": ["a"], "status": [], "privacyProtection": false},
			"whoisStatus": "ok", "at": "2026-10-09T12:00:00Z"
		}`)
	})
	res, err := c.IP.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.VPNProvider != "Mullvad" || res.Provider != "M247" || res.Verdict.Evidence[0] != "vpn_server_list" || res.Purity.Grade != "C" {
		t.Errorf("unexpected result: %+v", res)
	}
	if res.WhoisStatus != "ok" || res.Whois.Registrar != "R" || res.Locked != nil {
		t.Errorf("unexpected whois: %+v", res)
	}
}

func TestVPNAndProxyFields(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/vpn/1.2.3.4" {
			io.WriteString(w, `{"ip":"1.2.3.4","isVpn":true,"isTor":false,"networkClass":"vpn","anonymized":true,"provider":"M247","vpnProvider":"Proton VPN","riskScore":90,"evidence":["vpn_operator"]}`)
			return
		}
		io.WriteString(w, `{"ip":"1.2.3.4","isProxy":false,"isTor":false,"networkClass":"relay","anonymized":true,"provider":null,"vpnProvider":null,"riskScore":40,"evidence":["relay_range"],"locked":["provider","vpnProvider"],"planRequired":"Starter"}`)
	})
	vpn, err := c.IP.VPN(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if vpn.VPNProvider != "Proton VPN" || vpn.Provider != "M247" || vpn.Evidence[0] != "vpn_operator" || vpn.Locked != nil {
		t.Errorf("vpn = %+v", vpn)
	}
	proxy, err := c.IP.Proxy(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if proxy.NetworkClass != "relay" || proxy.Provider != "" || proxy.VPNProvider != "" || len(proxy.Locked) != 2 || proxy.PlanRequired != "Starter" {
		t.Errorf("proxy = %+v", proxy)
	}
}

func TestGeoLocked(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"ip":"1.2.3.4","country":"Germany","countryCode":"DE","city":"Berlin","region":"BE","postalCode":null,"latitude":null,"longitude":null,"timezone":"Europe/Berlin","accuracyRadius":null,"locked":["latitude","longitude","postalCode","accuracyRadius"],"planRequired":"Starter"}`)
	})
	g, err := c.IP.Geo(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if g.City != "Berlin" || g.Latitude != 0 || len(g.Locked) != 4 || g.PlanRequired != "Starter" {
		t.Errorf("geo = %+v", g)
	}
}

func TestWhoisStatus(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"domain":"example.com","registrar":"","registeredOn":"","expiresOn":"","lastUpdated":"","nameservers":[],"status":[],"privacyProtection":false,"whoisStatus":"unavailable"}`)
	})
	wi, err := c.IP.Whois(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if wi.WhoisStatus != "unavailable" || wi.Registrar != "" || len(wi.Nameservers) != 0 {
		t.Errorf("whois = %+v", wi)
	}
}
