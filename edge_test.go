package ipscanner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

func TestEdgeCheck(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/edge/check" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer pk_test_123" {
			t.Errorf("Authorization = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		want := `{"site":"site_abc","ip":"185.65.134.1","user_agent":"curl/8","headless_flags":{"webdriver":true},"request_id":"r1"}`
		if string(body) != want {
			t.Errorf("body = %s\nwant   %s", body, want)
		}
		io.WriteString(w, `{
			"class": "vpn",
			"agent": {"class": "ai_agent", "confidence": 0.7, "action": "flag", "signals": {"scripted_client": "curl", "network_origin": "vpn"}},
			"network": {"networkClass": "vpn", "anonymized": true, "riskScore": 90, "provider": "M247", "vpnProvider": "Mullvad",
				"evidence": ["vpn_server_list", "vpn_operator"], "country": "SE", "asn": 9009, "asnName": "M247 Europe SRL", "extra": 1},
			"site": {"id": "site_abc", "mode": "monitor", "policyVersion": 3},
			"newField": {"x": [1, 2]}
		}`)
	})
	res, err := c.Edge.Check(context.Background(), EdgeCheckParams{
		Site: "site_abc", IP: "185.65.134.1", UserAgent: "curl/8", HeadlessFlags: map[string]bool{"webdriver": true}, RequestID: "r1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Class != "vpn" || res.Agent.Signals["scripted_client"] != "curl" || res.Site.PolicyVersion != 3 {
		t.Errorf("unexpected result: %+v", res)
	}
	n := res.Network
	if n.VPNProvider != "Mullvad" || n.Provider != "M247" || n.ASN != 9009 || len(n.Evidence) != 2 || n.Evidence[1] != "vpn_operator" {
		t.Errorf("network = %+v", n)
	}
	if res.Locked != nil || res.PlanRequired != "" {
		t.Errorf("unexpected markers: %+v", res)
	}
}

func TestEdgeCheckLockedAndDegraded(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{
			"class": "relay", "agent": null, "site": null, "degraded": ["agent"],
			"network": {"networkClass": "relay", "anonymized": true, "riskScore": 40, "provider": null, "vpnProvider": null, "evidence": ["relay_range"], "asn": 13335},
			"locked": ["network.provider", "network.vpnProvider"], "planRequired": "Starter"
		}`)
	})
	res, err := c.Edge.Check(context.Background(), EdgeCheckParams{IP: "172.224.226.1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Agent != nil || res.Site != nil || len(res.Degraded) != 1 {
		t.Errorf("unexpected result: %+v", res)
	}
	if res.Network.Provider != "" || res.Network.VPNProvider != "" || res.Network.NetworkClass != "relay" {
		t.Errorf("network = %+v", res.Network)
	}
	if len(res.Locked) != 2 || res.Locked[0] != "network.provider" || res.PlanRequired != "Starter" {
		t.Errorf("markers = %v %q", res.Locked, res.PlanRequired)
	}
}

func TestSitesPolicy(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.RequestURI != "/v1/sites/site%20a/policy" {
			t.Errorf("%s %s", r.Method, r.RequestURI)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer pk_test_123" {
			t.Errorf("Authorization = %q", got)
		}
		io.WriteString(w, `{"site":"site a","mode":"enforce","policy":{"verified_bot":"allow","tor":"block","relay":"flag"},"version":7,"updatedAt":"2026-10-08T09:30:00.5Z"}`)
	})
	p, err := c.Sites.Policy(context.Background(), "site a")
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != "enforce" || p.Policy["tor"] != "block" || p.Version != 7 || p.UpdatedAt.IsZero() {
		t.Errorf("unexpected policy: %+v", p)
	}
}

func TestSitesPolicyUnknown(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, map[string]any{"error": "unknown_site", "message": "No site with this id on this account"})
	})
	_, err := c.Sites.Policy(context.Background(), "nope")
	if !IsNotFound(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestGateVerify(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/gate/verify" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if _, ok := r.Header["Authorization"]; ok {
			t.Errorf("unexpected Authorization header")
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		want := `{"secret":"gs_secret","token":"tok","remote_ip":"1.2.3.4"}`
		if string(body) != want {
			t.Errorf("body = %s\nwant   %s", body, want)
		}
		io.WriteString(w, `{"success":true,"class":"vpn","action":"block","mode":"enforce","confidence":0.95,
			"network":{"classification":"vpn","anonymized":true,"provider":"M247","vpn_provider":"NordVPN"},
			"signals":["vpn_server_list"],"hostname":"example.com","issued_at":"2026-10-09T10:00:00Z","ip_match":true}`)
	})
	v, err := c.Gate.Verify(context.Background(), GateVerifyParams{Secret: "gs_secret", Token: "tok", RemoteIP: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Success || v.Action != "block" || v.Network.VPNProvider != "NordVPN" || v.Network.Provider != "M247" || !v.IPMatch || v.IssuedAt.IsZero() {
		t.Errorf("unexpected verification: %+v", v)
	}
	if calls != 1 {
		t.Errorf("calls = %d", calls)
	}
}

func TestGateVerifyLockedNoRemoteIP(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"secret":"gs_secret","token":"tok"}` {
			t.Errorf("body = %s", body)
		}
		io.WriteString(w, `{"success":true,"class":"human","action":"allow","mode":"monitor","confidence":0.8,
			"network":{"classification":"residential_clean","anonymized":false,"provider":null,"vpn_provider":null},
			"signals":[],"hostname":"example.com","issued_at":"2026-10-09T10:00:00Z","ip_match":true,
			"locked":["network.provider","network.vpn_provider"],"planRequired":"Starter"}`)
	})
	v, err := c.Gate.Verify(context.Background(), GateVerifyParams{Secret: "gs_secret", Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Network.Provider != "" || v.Network.VPNProvider != "" || len(v.Locked) != 2 || v.PlanRequired != "Starter" {
		t.Errorf("unexpected verification: %+v", v)
	}
}

func TestGateVerifyErrors(t *testing.T) {
	cases := []struct {
		status int
		code   string
		auth   bool
	}{
		{401, "invalid_secret", true},
		{400, "already_used", false},
		{400, "expired_token", false},
		{503, "unavailable", false},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			calls := 0
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				writeJSON(w, tc.status, map[string]any{"success": false, "error": tc.code, "message": "m"})
			})
			_, err := c.Gate.Verify(context.Background(), GateVerifyParams{Secret: "gs_x", Token: "tok"})
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Status != tc.status || apiErr.Code != tc.code || apiErr.Message != "m" {
				t.Fatalf("err = %v", err)
			}
			if IsAuth(err) != tc.auth {
				t.Errorf("IsAuth = %v", IsAuth(err))
			}
			if calls != 1 {
				t.Errorf("calls = %d, want 1 (never retried)", calls)
			}
		})
	}
}
