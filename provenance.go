package ipscanner

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ProvenanceService records and verifies tamper-evident jurisdiction attestations.
type ProvenanceService struct{ c *Client }

// ProvenanceCheckParams is the input for Provenance.Check.
type ProvenanceCheckParams struct {
	IP                  string         `json:"ip"`
	ClaimedJurisdiction string         `json:"claimed_jurisdiction,omitempty"`
	RequestContext      map[string]any `json:"request_context,omitempty"`
}

// ProvenanceCheckResult is the policy decision and the ID of the attestation written.
type ProvenanceCheckResult struct {
	NetworkOrigin string  `json:"network_origin"`
	Anonymized    bool    `json:"anonymized"`
	Method        string  `json:"method"`
	Confidence    float64 `json:"confidence"`
	PolicyAction  string  `json:"policy_action"`
	AttestationID int64   `json:"attestation_id"`
}

// ChainVerification is the result of verifying the attestation chain.
type ChainVerification struct {
	OK       bool  `json:"ok"`
	Count    int64 `json:"count"`
	BrokenAt int64 `json:"brokenAt"`
}

// AnchoredVerification is a fresh chain verification with the latest daily anchor.
type AnchoredVerification struct {
	OK       bool      `json:"ok"`
	Count    int64     `json:"count"`
	BrokenAt int64     `json:"brokenAt"`
	Yours    int64     `json:"yours"`
	Anchor   *Anchor   `json:"anchor"`
	At       time.Time `json:"at"`
}

// Anchor is a daily root hash sealing the chain up to LastID.
type Anchor struct {
	Day      string `json:"day"`
	RootHash string `json:"rootHash"`
	LastID   int64  `json:"lastId"`
}

// ChainParams pages through Provenance.Chain. Zero values are omitted.
type ChainParams struct {
	Limit  int
	Before int64
}

// ChainPage is a page of attestation chain links.
type ChainPage struct {
	Links         []ChainLink    `json:"links"`
	NextBefore    int64          `json:"nextBefore"`
	Total         int64          `json:"total"`
	Summary       ChainSummary   `json:"summary"`
	Anchor        *Anchor        `json:"anchor"`
	Jurisdictions []Jurisdiction `json:"jurisdictions"`
	AsOf          time.Time      `json:"asOf"`
}

// ChainLink is one attestation with its hash-chain status.
type ChainLink struct {
	ID                  int64     `json:"id"`
	Ts                  time.Time `json:"ts"`
	IP                  string    `json:"ip"`
	ClaimedJurisdiction string    `json:"claimedJurisdiction"`
	NetworkOrigin       string    `json:"networkOrigin"`
	Anonymized          bool      `json:"anonymized"`
	Method              string    `json:"method"`
	Confidence          float64   `json:"confidence"`
	PolicyAction        string    `json:"policyAction"`
	EntryHash           string    `json:"entryHash"`
	PrevHash            string    `json:"prevHash"`
	PrevID              int64     `json:"prevId"`
	EntryOK             bool      `json:"entryOk"`
	LinkOK              bool      `json:"linkOk"`
}

// ChainSummary counts attestations by policy action.
type ChainSummary struct {
	Allow  int64 `json:"allow"`
	StepUp int64 `json:"step_up"`
	Block  int64 `json:"block"`
}

// Jurisdiction is one policy the engine knows.
type Jurisdiction struct {
	Code         string `json:"code"`
	Label        string `json:"label"`
	Law          string `json:"law,omitempty"`
	Strict       bool   `json:"strict"`
	CleanAction  string `json:"cleanAction"`
	MaskedAction string `json:"maskedAction"`
	Rule         string `json:"rule"`
}

// ExportParams bounds Provenance.Export. From and To accept RFC3339 or YYYY-MM-DD.
type ExportParams struct {
	From string
	To   string
}

// Check classifies an address against a claimed jurisdiction and writes an attestation.
func (s *ProvenanceService) Check(ctx context.Context, params ProvenanceCheckParams) (*ProvenanceCheckResult, error) {
	var out ProvenanceCheckResult
	if err := s.c.post(ctx, "/v1/provenance/check", params, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Verify verifies the account's attestation chain.
func (s *ProvenanceService) Verify(ctx context.Context) (*ChainVerification, error) {
	var out ChainVerification
	if err := s.c.get(ctx, "/v1/provenance/verify", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyAnchored verifies the chain now and returns the latest anchor.
func (s *ProvenanceService) VerifyAnchored(ctx context.Context) (*AnchoredVerification, error) {
	var out AnchoredVerification
	if err := s.c.post(ctx, "/v1/provenance/verify", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Chain returns a page of attestations, newest first. params may be nil.
func (s *ProvenanceService) Chain(ctx context.Context, params *ChainParams) (*ChainPage, error) {
	q := url.Values{}
	if params != nil {
		if params.Limit > 0 {
			q.Set("limit", strconv.Itoa(params.Limit))
		}
		if params.Before > 0 {
			q.Set("before", strconv.FormatInt(params.Before, 10))
		}
	}
	var out ChainPage
	if err := s.c.get(ctx, "/v1/provenance/chain", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Jurisdictions lists the jurisdictions the policy engine knows.
func (s *ProvenanceService) Jurisdictions(ctx context.Context) ([]Jurisdiction, error) {
	var out struct {
		Jurisdictions []Jurisdiction `json:"jurisdictions"`
	}
	if err := s.c.get(ctx, "/v1/provenance/jurisdictions", nil, &out); err != nil {
		return nil, err
	}
	return out.Jurisdictions, nil
}

// Export returns the signed evidence export as raw CSV. params may be nil.
func (s *ProvenanceService) Export(ctx context.Context, params *ExportParams) ([]byte, error) {
	q := url.Values{}
	if params != nil {
		if params.From != "" {
			q.Set("from", params.From)
		}
		if params.To != "" {
			q.Set("to", params.To)
		}
	}
	return s.c.doRaw(ctx, http.MethodGet, "/v1/provenance/export", q, nil, "text/csv", true)
}
