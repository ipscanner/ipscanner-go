package ipscanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// APIError is returned when the API responds with a non-2xx status.
type APIError struct {
	Status  int
	Code    string
	Message string
	Details map[string]any
	Body    []byte
}

func (e *APIError) Error() string {
	return fmt.Sprintf("ipscanner: %d %s: %s", e.Status, e.Code, e.Message)
}

// Invalid returns details.invalid from a bulk 400 response.
func (e *APIError) Invalid() []string {
	raw, _ := e.Details["invalid"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// RateLimitError is returned for HTTP 429 responses. errors.As also matches it as *APIError.
type RateLimitError struct {
	APIError
	Reason          string
	RetryAfter      time.Duration
	ResetAt         time.Time
	ResetDate       string
	Limit           int64
	Usage           int64
	Remaining       int64
	Needed          int64
	Plan            string
	SoftBlock       bool
	UpgradeURL      string
	RecommendedPlan string
	RateLimit       RateLimitHeaders
}

func (e *RateLimitError) Error() string { return e.APIError.Error() }

func (e *RateLimitError) Unwrap() error { return &e.APIError }

// RateLimitHeaders holds the X-RateLimit-* and X-Quota-* response headers.
type RateLimitHeaders struct {
	Meter           string
	Limit           int64
	Remaining       int64
	Reset           time.Time
	DailyLimit      int64
	DailyRemaining  int64
	DailyReset      time.Time
	HourlyLimit     int64
	HourlyRemaining int64
	HourlyReset     time.Time
	UsagePercent    int64
	UpgradeHint     string
	UpgradeURL      string
	UpgradePlan     string
	RetryAfter      time.Duration
}

// ConnectionError is returned when the request could not be completed, including timeouts.
type ConnectionError struct {
	Err error
}

func (e *ConnectionError) Error() string { return "ipscanner: connection error: " + e.Err.Error() }

func (e *ConnectionError) Unwrap() error { return e.Err }

// IsNotFound reports whether err is a 404 API error.
func IsNotFound(err error) bool { return statusOf(err) == http.StatusNotFound }

// IsAuth reports whether err is a 401 or 403 API error.
func IsAuth(err error) bool {
	s := statusOf(err)
	return s == http.StatusUnauthorized || s == http.StatusForbidden
}

// IsRateLimited reports whether err is a 429 API error.
func IsRateLimited(err error) bool { return statusOf(err) == http.StatusTooManyRequests }

func statusOf(err error) int {
	var e *APIError
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

type errorBody struct {
	Error      string         `json:"error"`
	Message    string         `json:"message"`
	Details    map[string]any `json:"details"`
	Reason     string         `json:"reason"`
	Plan       string         `json:"plan"`
	Limit      int64          `json:"limit"`
	Usage      int64          `json:"usage"`
	Remaining  int64          `json:"remaining"`
	Needed     int64          `json:"needed"`
	ResetDate  string         `json:"resetDate"`
	ResetAt    string         `json:"resetAt"`
	RetryAfter *int64         `json:"retryAfter"`
	SoftBlock  bool           `json:"softBlock"`
	Upgrade    *struct {
		RecommendedPlan string `json:"recommendedPlan"`
		URL             string `json:"url"`
	} `json:"upgrade"`
}

func newError(resp *http.Response, data []byte) error {
	var b errorBody
	apiErr := APIError{Status: resp.StatusCode, Body: data}
	if json.Unmarshal(data, &b) == nil && b.Error != "" {
		apiErr.Code = b.Error
		apiErr.Message = b.Message
		apiErr.Details = b.Details
	} else {
		apiErr.Code = "http_" + strconv.Itoa(resp.StatusCode)
		apiErr.Message = http.StatusText(resp.StatusCode)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		return &apiErr
	}

	h := parseRateLimitHeaders(resp.Header)
	e := &RateLimitError{
		APIError:        apiErr,
		Reason:          b.Reason,
		RetryAfter:      h.RetryAfter,
		ResetDate:       b.ResetDate,
		Limit:           b.Limit,
		Usage:           b.Usage,
		Remaining:       b.Remaining,
		Needed:          b.Needed,
		Plan:            b.Plan,
		SoftBlock:       b.SoftBlock,
		UpgradeURL:      h.UpgradeURL,
		RecommendedPlan: h.UpgradePlan,
		RateLimit:       h,
	}
	if b.RetryAfter != nil {
		e.RetryAfter = time.Duration(*b.RetryAfter) * time.Second
	}
	if t, err := time.Parse(time.RFC3339, b.ResetAt); err == nil {
		e.ResetAt = t
	}
	if b.Upgrade != nil {
		if b.Upgrade.URL != "" {
			e.UpgradeURL = b.Upgrade.URL
		}
		if b.Upgrade.RecommendedPlan != "" {
			e.RecommendedPlan = b.Upgrade.RecommendedPlan
		}
	}
	return e
}

func parseRateLimitHeaders(h http.Header) RateLimitHeaders {
	return RateLimitHeaders{
		Meter:           h.Get("X-RateLimit-Meter"),
		Limit:           headerInt(h, "X-RateLimit-Limit"),
		Remaining:       headerInt(h, "X-RateLimit-Remaining"),
		Reset:           headerUnix(h, "X-RateLimit-Reset"),
		DailyLimit:      headerInt(h, "X-RateLimit-Daily-Limit"),
		DailyRemaining:  headerInt(h, "X-RateLimit-Daily-Remaining"),
		DailyReset:      headerUnix(h, "X-RateLimit-Daily-Reset"),
		HourlyLimit:     headerInt(h, "X-RateLimit-Hourly-Limit"),
		HourlyRemaining: headerInt(h, "X-RateLimit-Hourly-Remaining"),
		HourlyReset:     headerUnix(h, "X-RateLimit-Hourly-Reset"),
		UsagePercent:    headerInt(h, "X-RateLimit-Usage-Percent"),
		UpgradeHint:     h.Get("X-Quota-Upgrade-Hint"),
		UpgradeURL:      h.Get("X-Quota-Upgrade-Url"),
		UpgradePlan:     h.Get("X-Quota-Upgrade-Plan"),
		RetryAfter:      retryAfter(h.Get("Retry-After")),
	}
}

func headerInt(h http.Header, key string) int64 {
	n, _ := strconv.ParseInt(h.Get(key), 10, 64)
	return n
}

func headerUnix(h http.Header, key string) time.Time {
	n := headerInt(h, key)
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

func retryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
