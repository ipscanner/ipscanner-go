package ipscanner

import (
	"context"
	"time"
)

// GateService redeems form gate tokens on the site's server.
type GateService struct{ c *Client }

// GateVerifyParams is the input for Gate.Verify. Secret is the site secret (gs_...).
type GateVerifyParams struct {
	Secret   string `json:"secret"`
	Token    string `json:"token"`
	RemoteIP string `json:"remote_ip,omitempty"`
}

// GateVerification is the response of POST /v1/gate/verify.
type GateVerification struct {
	Success      bool        `json:"success"`
	Class        string      `json:"class"`
	Action       string      `json:"action"`
	Mode         string      `json:"mode"`
	Confidence   float64     `json:"confidence"`
	Network      GateNetwork `json:"network"`
	Signals      []string    `json:"signals"`
	Hostname     string      `json:"hostname"`
	IssuedAt     time.Time   `json:"issued_at"`
	IPMatch      bool        `json:"ip_match"`
	Locked       []string    `json:"locked,omitempty"`
	PlanRequired string      `json:"planRequired,omitempty"`
}

// GateNetwork is the network of a gate verification. Provider and VPNProvider are empty when unknown or locked.
type GateNetwork struct {
	Classification string `json:"classification"`
	Anonymized     bool   `json:"anonymized"`
	Provider       string `json:"provider"`
	VPNProvider    string `json:"vpn_provider"`
}

// Verify redeems a gate token. It sends no API key and is never retried.
func (s *GateService) Verify(ctx context.Context, params GateVerifyParams) (*GateVerification, error) {
	var out GateVerification
	if err := s.c.postKeyless(ctx, "/v1/gate/verify", params, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
