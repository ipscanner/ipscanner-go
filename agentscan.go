package ipscanner

import (
	"context"
	"time"
)

// AgentscanService classifies requests as human, known bot, AI agent or malicious automation.
type AgentscanService struct{ c *Client }

// AgentscanCheckParams is the input for Agentscan.Check.
type AgentscanCheckParams struct {
	IP            string            `json:"ip"`
	UserAgent     string            `json:"user_agent,omitempty"`
	JA4           string            `json:"ja4,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	HeadlessFlags map[string]bool   `json:"headless_flags,omitempty"`
	RequestID     string            `json:"request_id,omitempty"`
}

// AgentscanVerdict is the classification of one request.
type AgentscanVerdict struct {
	Class      string         `json:"class"`
	Confidence float64        `json:"confidence"`
	Action     string         `json:"action"`
	Signals    map[string]any `json:"signals"`
}

// AgentscanBatchLine is one access-log line for Agentscan.Batch.
type AgentscanBatchLine struct {
	Line      int               `json:"line"`
	IP        string            `json:"ip"`
	UserAgent string            `json:"user_agent,omitempty"`
	JA4       string            `json:"ja4,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
}

// AgentscanBatchResult is the response of Agentscan.Batch.
type AgentscanBatchResult struct {
	Submitted int                     `json:"submitted"`
	Processed int                     `json:"processed"`
	Failed    int                     `json:"failed"`
	Truncated bool                    `json:"truncated"`
	Reason    string                  `json:"reason"`
	ByClass   map[string]int          `json:"byClass"`
	Results   []AgentscanBatchOutcome `json:"results"`
	AsOf      time.Time               `json:"asOf"`
}

// AgentscanBatchOutcome is the result for one batch line. Error is set when the line failed.
type AgentscanBatchOutcome struct {
	Line       int            `json:"line"`
	IP         string         `json:"ip"`
	UserAgent  string         `json:"userAgent,omitempty"`
	Class      string         `json:"class,omitempty"`
	Confidence float64        `json:"confidence,omitempty"`
	Action     string         `json:"action,omitempty"`
	Signals    map[string]any `json:"signals,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// AgentscanVerifyParams is the input for Agentscan.Verify. Set Bot or UserAgent.
type AgentscanVerifyParams struct {
	IP        string `json:"ip"`
	Bot       string `json:"bot,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

// CrawlerVerification is the result of checking a claimed crawler against its published evidence.
type CrawlerVerification struct {
	IP            string        `json:"ip"`
	Slug          string        `json:"slug"`
	Crawler       string        `json:"crawler"`
	UserAgent     string        `json:"userAgent,omitempty"`
	Outcome       string        `json:"outcome"`
	Method        string        `json:"method"`
	Summary       string        `json:"summary"`
	Checks        []VerifyCheck `json:"checks"`
	NetworkOrigin string        `json:"networkOrigin"`
	Anonymized    bool          `json:"anonymized"`
	ASN           string        `json:"asn,omitempty"`
	ASNName       string        `json:"asnName,omitempty"`
	Country       string        `json:"country,omitempty"`
	Hostname      string        `json:"hostname,omitempty"`
	Docs          string        `json:"docs,omitempty"`
	CheckedAt     time.Time     `json:"checkedAt"`
}

// VerifyCheck is one piece of evidence in a CrawlerVerification.
type VerifyCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// AllowlistAgent is an allowlisted bot or crawler. CustomerID is nil for global entries.
type AllowlistAgent struct {
	ID                 int64     `json:"id"`
	Ident              string    `json:"ident"`
	Type               string    `json:"type"`
	VerificationMethod string    `json:"verificationMethod"`
	CustomerID         *int      `json:"customerId"`
	CreatedAt          time.Time `json:"createdAt"`
}

// AgentscanSelfCheckParams is the optional input for Agentscan.SelfCheck.
type AgentscanSelfCheckParams struct {
	IP        string            `json:"ip,omitempty"`
	UserAgent string            `json:"user_agent,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	JA4       string            `json:"ja4,omitempty"`
}

// AgentscanSelfCheckResult is the classification of the calling connection.
type AgentscanSelfCheckResult struct {
	IP           string         `json:"ip"`
	UserAgent    string         `json:"userAgent"`
	JA4          string         `json:"ja4"`
	JA4Source    string         `json:"ja4Source"`
	Class        string         `json:"class"`
	Confidence   float64        `json:"confidence"`
	Action       string         `json:"action"`
	Signals      map[string]any `json:"signals"`
	Metered      bool           `json:"metered"`
	AsOf         time.Time      `json:"asOf"`
	ASN          *ASNInfo       `json:"asn,omitempty"`
	Geo          *Geolocation   `json:"geo,omitempty"`
	Locked       []string       `json:"locked,omitempty"`
	PlanRequired string         `json:"planRequired,omitempty"`
}

// Check classifies one request.
func (s *AgentscanService) Check(ctx context.Context, params AgentscanCheckParams) (*AgentscanVerdict, error) {
	var out AgentscanVerdict
	if err := s.c.post(ctx, "/v1/agentscan/check", params, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Batch classifies up to 25,000 parsed access-log lines.
func (s *AgentscanService) Batch(ctx context.Context, lines []AgentscanBatchLine) (*AgentscanBatchResult, error) {
	var out AgentscanBatchResult
	body := struct {
		Lines []AgentscanBatchLine `json:"lines"`
	}{lines}
	if err := s.c.post(ctx, "/v1/agentscan/batch", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Verify checks whether an address really belongs to the crawler it claims to be.
func (s *AgentscanService) Verify(ctx context.Context, params AgentscanVerifyParams) (*CrawlerVerification, error) {
	var out CrawlerVerification
	if err := s.c.post(ctx, "/v1/agentscan/verify", params, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Allowlist returns the allowlist entries in effect for the account.
func (s *AgentscanService) Allowlist(ctx context.Context) ([]AllowlistAgent, error) {
	var out struct {
		Agents []AllowlistAgent `json:"agents"`
	}
	if err := s.c.get(ctx, "/v1/agentscan/allowlist", nil, &out); err != nil {
		return nil, err
	}
	return out.Agents, nil
}

// SelfCheck classifies the calling connection. params may be nil. Not metered.
func (s *AgentscanService) SelfCheck(ctx context.Context, params *AgentscanSelfCheckParams) (*AgentscanSelfCheckResult, error) {
	if params == nil {
		params = &AgentscanSelfCheckParams{}
	}
	var out AgentscanSelfCheckResult
	if err := s.c.post(ctx, "/v1/agentscan/self", params, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
