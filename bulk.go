package ipscanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"time"
)

const streamTimeout = 5 * time.Minute

// BulkService covers batch IP checks.
type BulkService struct{ c *Client }

// BulkParams is the input for Bulk.Check and Bulk.Stream. Set IPs, Input, or both.
type BulkParams struct {
	IPs   []string `json:"ips,omitempty"`
	Input string   `json:"input,omitempty"`
}

// BulkCheckResult is the response of POST /v1/bulk/check.
type BulkCheckResult struct {
	Submitted    int            `json:"submitted"`
	Unique       int            `json:"unique"`
	Duplicates   int            `json:"duplicates"`
	Invalid      []string       `json:"invalid"`
	Summary      map[string]int `json:"summary"`
	Results      []BulkResult   `json:"results"`
	PlanRequired string         `json:"planRequired,omitempty"`
}

// BulkResult is one graded address in a bulk check.
type BulkResult struct {
	Input             string      `json:"input"`
	IP                string      `json:"ip"`
	Port              int         `json:"port,omitempty"`
	Score             int         `json:"score"`
	Grade             string      `json:"grade"`
	Verdict           string      `json:"verdict"`
	Classification    string      `json:"classification"`
	Confidence        float64     `json:"confidence"`
	Anonymized        bool        `json:"anonymized"`
	VPNProvider       string      `json:"vpnProvider,omitempty"`
	IsTorExit         bool        `json:"isTorExit"`
	InVPNRange        bool        `json:"inVpnRange"`
	InDatacenterRange bool        `json:"inDatacenterRange"`
	ASN               string      `json:"asn,omitempty"`
	ASNName           string      `json:"asnName,omitempty"`
	ASNType           string      `json:"asnType,omitempty"`
	Country           string      `json:"country,omitempty"`
	Deductions        []Deduction `json:"deductions"`
	Locked            []string    `json:"locked,omitempty"`
}

// BulkEvent is one line of the Bulk.Stream response. Type is meta, result, error or done.
type BulkEvent struct {
	Type           string   `json:"type"`
	Index          int      `json:"index"`
	Total          int      `json:"total"`
	Input          string   `json:"input"`
	Reason         string   `json:"reason"`
	Message        string   `json:"message"`
	Error          string   `json:"error"`
	IP             string   `json:"ip"`
	Verdict        string   `json:"verdict"`
	Classification string   `json:"classification"`
	Confidence     float64  `json:"confidence"`
	Anonymized     bool     `json:"anonymized"`
	VPNProvider    string   `json:"vpnProvider"`
	Score          int      `json:"score"`
	Grade          string   `json:"grade"`
	IsTorExit      bool     `json:"isTorExit"`
	ASN            string   `json:"asn"`
	ASNName        string   `json:"asnName"`
	ASNType        string   `json:"asnType"`
	Country        string   `json:"country"`
	Processed      int      `json:"processed"`
	Failed         int      `json:"failed"`
	Metered        int      `json:"metered"`
	PlanRequired   string   `json:"planRequired"`
	Locked         []string `json:"locked"`
}

// Complete reports whether a done event covers every address in the run.
func (e *BulkEvent) Complete() bool {
	return e.Type == "done" && e.Reason == "complete" && e.Processed+e.Failed >= e.Total
}

// Check grades up to the plan's bulk cap of addresses in one response.
func (s *BulkService) Check(ctx context.Context, params BulkParams) (*BulkCheckResult, error) {
	var out BulkCheckResult
	if err := s.c.post(ctx, "/v1/bulk/check", params, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Stream grades addresses and yields one event per NDJSON line as it arrives.
// A 5 minute timeout applies unless ctx already has a deadline.
func (s *BulkService) Stream(ctx context.Context, params BulkParams) iter.Seq2[*BulkEvent, error] {
	return func(yield func(*BulkEvent, error) bool) {
		ctx := ctx
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, streamTimeout)
			defer cancel()
		}

		resp, err := s.c.send(ctx, http.MethodPost, "/v1/ip/bulk", nil, params, "application/x-ndjson", true)
		if err != nil {
			yield(nil, err)
			return
		}
		defer resp.Body.Close()

		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
		done := false
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var ev BulkEvent
			if err := json.Unmarshal(line, &ev); err != nil {
				yield(nil, fmt.Errorf("ipscanner: decode stream line: %w", err))
				return
			}
			done = ev.Type == "done"
			if !yield(&ev, nil) {
				return
			}
		}
		if err := sc.Err(); err != nil {
			yield(nil, &ConnectionError{Err: err})
			return
		}
		if !done {
			yield(nil, &ConnectionError{Err: io.ErrUnexpectedEOF})
		}
	}
}
