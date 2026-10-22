package ipscanner

import (
	"context"
	"io"
	"net/http"
	"testing"
)

func TestEmailCheck(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/email/check" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer pk_test_123" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"email":"jane@outlok.com"}` {
			t.Errorf("body = %s", body)
		}
		io.WriteString(w, `{"email":"jane@outlok.com","status":"risky","reason":"typo","suggestion":"jane@outlook.com",
			"domain":"outlok.com","checks":{"syntax":true,"mx":null,"disposable":false,"role":false,"freeProvider":false},
			"mailbox":"not_checked"}`)
	})
	res, err := c.Email.Check(context.Background(), "jane@outlok.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "risky" || res.Reason != "typo" || res.Suggestion != "jane@outlook.com" || res.Domain != "outlok.com" ||
		res.Checks.MX != nil || !res.Checks.Syntax || res.Mailbox != "not_checked" {
		t.Errorf("unexpected check: %+v", res)
	}
	if calls != 1 {
		t.Errorf("calls = %d", calls)
	}
}

func TestEmailCheckValidHasNoReason(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"email":"a@b.io","status":"valid","reason":null,"suggestion":null,"domain":"b.io",
			"checks":{"syntax":true,"mx":true,"disposable":false,"role":false,"freeProvider":false},"mailbox":"not_checked"}`)
	})
	res, err := c.Email.Check(context.Background(), "a@b.io")
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "" || res.Suggestion != "" || res.Checks.MX == nil || !*res.Checks.MX {
		t.Errorf("unexpected check: %+v", res)
	}
}

func TestGateVerifyWithEmail(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"secret":"gs_secret","token":"tok","email":"x@mailinator.com"}` {
			t.Errorf("body = %s", body)
		}
		io.WriteString(w, `{"success":true,"class":"human","action":"block","mode":"enforce","confidence":0.6,
			"network":{"classification":"residential_clean","anonymized":false,"provider":"Comcast","vpn_provider":null},
			"signals":[],"hostname":"example.com","issued_at":"2026-10-14T10:00:00Z","ip_match":true,
			"email":{"status":"risky","reason":"disposable","suggestion":null,"domain":"mailinator.com","action":"block"}}`)
	})
	v, err := c.Gate.Verify(context.Background(), GateVerifyParams{Secret: "gs_secret", Token: "tok", Email: "x@mailinator.com"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Email == nil || v.Email.Reason != "disposable" || v.Email.Action != "block" || v.Email.Domain != "mailinator.com" || v.Action != "block" {
		t.Errorf("unexpected verification: %+v (email %+v)", v, v.Email)
	}
}

func TestVPNPurityAndLockedCount(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/vpn/1.2.3.4" {
			io.WriteString(w, `{"ip":"1.2.3.4","isVpn":true,"isTor":false,"networkClass":"vpn","anonymized":true,"provider":"M247",
				"vpnProvider":"NordVPN","riskScore":90,"purity":{"score":40,"grade":"C","verdict":"dirty",
				"deductions":[{"factor":"vpn_range","points":30,"detail":"x"}]}}`)
			return
		}
		io.WriteString(w, `{"ip":"5.6.7.8","isProxy":false,"isTor":false,"networkClass":"hosting","anonymized":true,"provider":null,
			"vpnProvider":null,"riskScore":60,"purity":null,"deductionCount":3,"locked":["purity","provider","vpnProvider"],"planRequired":"Starter"}`)
	})
	v, err := c.IP.VPN(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if v.Purity == nil || v.Purity.Score != 40 || len(v.Purity.Deductions) != 1 || v.DeductionCount != nil {
		t.Errorf("paid vpn: %+v", v)
	}
	p, err := c.IP.Proxy(context.Background(), "5.6.7.8")
	if err != nil {
		t.Fatal(err)
	}
	if p.Purity != nil || p.DeductionCount == nil || *p.DeductionCount != 3 || len(p.Locked) != 3 {
		t.Errorf("locked proxy: %+v", p)
	}
}

func TestUserAgentVersion(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua != "ipscanner-go/0.3.1" {
			t.Errorf("User-Agent = %q", ua)
		}
		io.WriteString(w, `{"email":"a@b.io","status":"valid","domain":"b.io","checks":{},"mailbox":"not_checked"}`)
	})
	if _, err := c.Email.Check(context.Background(), "a@b.io"); err != nil {
		t.Fatal(err)
	}
}
