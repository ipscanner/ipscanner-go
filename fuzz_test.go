package ipscanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fuzzTransport struct {
	status int
	header http.Header
	body   []byte
	last   *http.Request
}

func (f *fuzzTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.last = r
	status := f.status
	if status == 0 {
		status = http.StatusOK
	}
	h := f.header
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(f.body)), Request: r}, nil
}

func fuzzClient(rt *fuzzTransport) *Client {
	c := NewClient(WithAPIKey("pk_test_fuzz"), WithBaseURL("https://api.ipscanner.test"), WithHTTPClient(&http.Client{Transport: rt}), WithMaxRetries(0))
	c.backoff = func(int) time.Duration { return 0 }
	return c
}

// FuzzPathSegment checks that a caller supplied IP, domain or site ID stays one path segment.
func FuzzPathSegment(f *testing.F) {
	for _, s := range []string{
		"8.8.8.8", "2001:db8::1", "::ffff:1.2.3.4", "fe80::1%eth0", "example.com", "site_abc123",
		"../account", "a/b", "1.1.1.1?x=1", "1.1.1.1#frag", "%2e%2e", " 1.1.1.1", "AS13335",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if s == "" {
			return
		}
		rt := &fuzzTransport{body: []byte(`{}`)}
		c := fuzzClient(rt)
		for _, call := range []struct {
			prefix, suffix string
			do             func() error
		}{
			{"/v1/vpn/", "", func() error { _, err := c.IP.VPN(context.Background(), s); return err }},
			{"/v1/whois/", "", func() error { _, err := c.IP.Whois(context.Background(), s); return err }},
			{"/v1/sites/", "/policy", func() error { _, err := c.Sites.Policy(context.Background(), s); return err }},
		} {
			rt.last = nil
			err := call.do()
			if rt.last == nil {
				if err == nil || (s != "." && s != "..") {
					t.Fatalf("%q: no request sent: %v", s, err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%q: %v", s, err)
			}
			u := rt.last.URL
			if u.RawQuery != "" || u.Fragment != "" || u.Host != "api.ipscanner.test" {
				t.Fatalf("%q escaped the path: %s", s, u)
			}
			p := u.EscapedPath()
			if !strings.HasPrefix(p, call.prefix) || !strings.HasSuffix(p, call.suffix) {
				t.Fatalf("%q: path %s", s, p)
			}
			seg := strings.TrimSuffix(strings.TrimPrefix(p, call.prefix), call.suffix)
			if strings.Contains(seg, "/") || seg == "." || seg == ".." {
				t.Fatalf("%q became path %s, not one segment", s, p)
			}
			if got, err := url.PathUnescape(seg); err != nil || got != s {
				t.Fatalf("%q sent as %q", s, seg)
			}
		}
	})
}

// FuzzErrorResponse checks the typed errors built from any non-2xx status, body and quota headers.
func FuzzErrorResponse(f *testing.F) {
	f.Add(429, []byte(`{"error":"quota_exceeded","message":"Monthly quota reached","reason":"monthly","retryAfter":3600,"resetAt":"2026-11-01T00:00:00Z","upgrade":{"url":"https://ipscanner.io/pricing","recommendedPlan":"starter"}}`), "120", "1767225600")
	f.Add(429, []byte(`{"error":"rate_limited","retryAfter":-5}`), "-1", "")
	f.Add(429, []byte(`not json`), "Wed, 21 Oct 2015 07:28:00 GMT", "x")
	f.Add(400, []byte(`{"error":"invalid_input","message":"bad","details":{"invalid":["x",1,null]}}`), "", "")
	f.Add(404, []byte(``), "", "")
	f.Add(503, []byte(`{"error":""}`), "9223372036854775807", "9223372036854775807")
	f.Fuzz(func(t *testing.T, status int, body []byte, retryAfter, reset string) {
		if status < 400 || status > 599 {
			return
		}
		h := http.Header{}
		h.Set("Retry-After", retryAfter)
		h.Set("X-RateLimit-Reset", reset)
		h.Set("X-RateLimit-Limit", reset)
		err := newError(&http.Response{StatusCode: status, Header: h}, body)
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != status || apiErr.Code == "" {
			t.Fatalf("%d: %#v", status, err)
		}
		if !strings.HasPrefix(err.Error(), "ipscanner: "+strconv.Itoa(status)) {
			t.Fatalf("message %q", err.Error())
		}
		_ = apiErr.Invalid()
		if IsNotFound(err) != (status == 404) || IsAuth(err) != (status == 401 || status == 403) || IsRateLimited(err) != (status == 429) {
			t.Fatalf("%d: classification mismatch", status)
		}
		var rl *RateLimitError
		if errors.As(err, &rl) != (status == 429) {
			t.Fatalf("%d: RateLimitError %v", status, rl != nil)
		}
		if rl != nil && (rl.RetryAfter < 0 || rl.RateLimit.RetryAfter < 0) {
			t.Fatalf("negative retry after: body %s header %q -> %s / %s", body, retryAfter, rl.RetryAfter, rl.RateLimit.RetryAfter)
		}
	})
}

// FuzzBulkStream checks that any NDJSON body ends in a done event or exactly one final error.
func FuzzBulkStream(f *testing.F) {
	f.Add([]byte("{\"type\":\"meta\",\"total\":2}\n{\"type\":\"result\",\"index\":0,\"ip\":\"1.1.1.1\",\"verdict\":\"clean\"}\n{\"type\":\"error\",\"index\":1,\"input\":\"x\",\"error\":\"invalid\"}\n{\"type\":\"done\",\"reason\":\"complete\",\"processed\":1,\"failed\":1,\"total\":2}\n"))
	f.Add([]byte("{\"type\":\"meta\"}\r\n\r\n{\"type\":\"result\"}"))
	f.Add([]byte("{\"type\":\"done\"}\n{\"type\":\"result\"}\n"))
	f.Add([]byte("null\n[1]\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, body []byte) {
		c := fuzzClient(&fuzzTransport{body: body})
		var events []*BulkEvent
		var errs []error
		for ev, err := range c.Bulk.Stream(context.Background(), BulkParams{IPs: []string{"1.1.1.1"}}) {
			if len(errs) > 0 {
				t.Fatal("yield after an error")
			}
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if ev == nil {
				t.Fatal("nil event without an error")
			}
			events = append(events, ev)
		}
		if len(errs) == 0 && (len(events) == 0 || events[len(events)-1].Type != "done") {
			t.Fatalf("stream ended without done and without an error: %d events", len(events))
		}
	})
}

// FuzzDecodeResponses checks that decoded responses re-encode to a stable form.
func FuzzDecodeResponses(f *testing.F) {
	f.Add(uint8(0), []byte(`{"target":{"raw":"1.1.1.1","kind":"ipv4","ip":"1.1.1.1"},"networkClass":"hosting","purity":{"score":70,"grade":"B","verdict":"suspect","deductions":[{"factor":"hosting","points":30,"detail":"x"}]},"geo":{"country":"US"},"at":"2026-10-06T12:00:00+02:00","deductionCount":3,"locked":["purity"]}`))
	f.Add(uint8(1), []byte(`{"class":"tor","agent":{"class":"human","confidence":0.9},"network":{"networkClass":"tor","anonymized":true,"riskScore":90,"asn":-1},"site":null,"degraded":[]}`))
	f.Add(uint8(2), []byte(`{"success":true,"class":"human","network":{"classification":"residential"},"issued_at":"2026-10-06T12:00:00.123456789Z","email":null}`))
	f.Add(uint8(3), []byte(`{"submitted":2,"invalid":["x"],"summary":{"clean":1},"results":[{"ip":"1.1.1.1","port":443}]}`))
	f.Add(uint8(4), []byte(`{"ip":"1.1.1.1","isVpn":true,"purity":null,"deductionCount":0}`))
	f.Fuzz(func(t *testing.T, kind uint8, body []byte) {
		newValue := []func() any{
			func() any { return new(LookupResult) },
			func() any { return new(EdgeCheckResult) },
			func() any { return new(GateVerification) },
			func() any { return new(BulkCheckResult) },
			func() any { return new(VPNInfo) },
		}[int(kind)%5]
		v := newValue()
		if json.Unmarshal(body, v) != nil {
			return
		}
		b1, err := json.Marshal(v)
		if err != nil {
			return // e.g. a time outside year 0-9999 cannot be encoded
		}
		v2 := newValue()
		if err := json.Unmarshal(b1, v2); err != nil {
			t.Fatalf("decode own encoding %s: %v", b1, err)
		}
		if b2, _ := json.Marshal(v2); !bytes.Equal(b1, b2) {
			t.Fatalf("round trip changed the response:\n%s\n%s", b1, b2)
		}
	})
}
