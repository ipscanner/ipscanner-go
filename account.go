package ipscanner

import (
	"context"
	"time"
)

// AccountService reports plan limits and usage.
type AccountService struct{ c *Client }

// Limits is the account's plan and monthly allowance.
type Limits struct {
	AccountType string  `json:"accountType"`
	Limit       int64   `json:"limit"`
	Usage       int64   `json:"usage"`
	Remaining   int64   `json:"remaining"`
	ResetDate   string  `json:"resetDate"`
	Daily       *Window `json:"daily"`
	Hourly      *Window `json:"hourly"`
}

// UsageSummary is the account's usage for the current period.
type UsageSummary struct {
	Plan        string    `json:"plan"`
	Used        int64     `json:"used"`
	Limit       int64     `json:"limit"`
	Unlimited   bool      `json:"unlimited"`
	Remaining   int64     `json:"remaining"`
	Percent     float64   `json:"percent"`
	SoftBlocked bool      `json:"softBlocked"`
	BlockedBy   string    `json:"blockedBy"`
	UpgradeHint bool      `json:"upgradeHint"`
	BulkCap     int       `json:"bulkCap"`
	Daily       *Window   `json:"daily"`
	Hourly      *Window   `json:"hourly"`
	PeriodStart string    `json:"periodStart"`
	ResetDate   string    `json:"resetDate"`
	AsOf        time.Time `json:"asOf"`
}

// Limits returns the account's plan limits.
func (s *AccountService) Limits(ctx context.Context) (*Limits, error) {
	var out Limits
	if err := s.c.get(ctx, "/v1/user/limits", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Usage returns the account's usage summary.
func (s *AccountService) Usage(ctx context.Context) (*UsageSummary, error) {
	var out UsageSummary
	if err := s.c.get(ctx, "/v1/usage/summary", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
