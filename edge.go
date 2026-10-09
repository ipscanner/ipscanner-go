package ipscanner

import "context"

// EdgeService runs the combined Agentscan and network check for one visitor.
type EdgeService struct{ c *Client }

// EdgeCheckParams is the input for Edge.Check.
type EdgeCheckParams struct {
	Site          string            `json:"site,omitempty"`
	IP            string            `json:"ip"`
	UserAgent     string            `json:"user_agent,omitempty"`
	JA4           string            `json:"ja4,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	HeadlessFlags map[string]bool   `json:"headless_flags,omitempty"`
	RequestID     string            `json:"request_id,omitempty"`
}

// EdgeCheckResult is the response of POST /v1/edge/check. Agent, Network and Site are nil when absent.
type EdgeCheckResult struct {
	Class        string            `json:"class"`
	Agent        *AgentscanVerdict `json:"agent"`
	Network      *EdgeNetwork      `json:"network"`
	Site         *EdgeSite         `json:"site"`
	Degraded     []string          `json:"degraded,omitempty"`
	Locked       []string          `json:"locked,omitempty"`
	PlanRequired string            `json:"planRequired,omitempty"`
}

// EdgeNetwork is the network half of an edge check. ASN is a number, not "AS..".
type EdgeNetwork struct {
	NetworkClass string   `json:"networkClass"`
	Anonymized   bool     `json:"anonymized"`
	RiskScore    int      `json:"riskScore"`
	Provider     string   `json:"provider,omitempty"`
	VPNProvider  string   `json:"vpnProvider,omitempty"`
	Evidence     []string `json:"evidence,omitempty"`
	Country      string   `json:"country,omitempty"`
	ASN          int64    `json:"asn,omitempty"`
	ASNName      string   `json:"asnName,omitempty"`
}

// EdgeSite is the site an edge check was attributed to.
type EdgeSite struct {
	ID            string `json:"id"`
	Mode          string `json:"mode"`
	PolicyVersion int    `json:"policyVersion"`
}

// Check classifies one visitor and attributes it to a site. Metered as 2 requests.
func (s *EdgeService) Check(ctx context.Context, params EdgeCheckParams) (*EdgeCheckResult, error) {
	var out EdgeCheckResult
	if err := s.c.post(ctx, "/v1/edge/check", params, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
