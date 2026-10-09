// Package ipscanner is the official Go client for the IPScanner API.
//
// See https://ipscanner.io/api-documentation for the full API reference.
package ipscanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Version is the SDK version sent in the User-Agent header.
const Version = "0.2.0"

// DefaultBaseURL is the API host used when no base URL is configured.
const DefaultBaseURL = "https://ipscanner.io"

const (
	defaultTimeout    = 30 * time.Second
	defaultMaxRetries = 2
)

// Client talks to the IPScanner API. Create one with NewClient and reuse it.
type Client struct {
	IP           *IPService
	Bulk         *BulkService
	Agentscan    *AgentscanService
	Provenance   *ProvenanceService
	Account      *AccountService
	ASNDirectory *ASNDirectoryService
	Crawlers     *CrawlersService
	Edge         *EdgeService
	Sites        *SitesService
	Gate         *GateService

	apiKey     string
	baseURL    string
	userAgent  string
	httpClient *http.Client
	timeout    time.Duration
	maxRetries int
	backoff    func(attempt int) time.Duration
}

// Option configures a Client.
type Option func(*Client)

// WithAPIKey sets the API key. Defaults to the IPSCANNER_API_KEY environment variable.
func WithAPIKey(key string) Option {
	return func(c *Client) { c.apiKey = key }
}

// WithBaseURL sets the API base URL. Defaults to IPSCANNER_API_URL or https://ipscanner.io.
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = u }
}

// WithHTTPClient sets the underlying HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithTimeout sets the per-request timeout applied when the context has no deadline. Zero disables it.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithMaxRetries sets how many times a failed GET request is retried. Defaults to 2.
func WithMaxRetries(n int) Option {
	return func(c *Client) { c.maxRetries = n }
}

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) Option {
	return func(c *Client) { c.userAgent = ua }
}

// NewClient returns a configured Client.
func NewClient(opts ...Option) *Client {
	c := &Client{
		apiKey:     os.Getenv("IPSCANNER_API_KEY"),
		baseURL:    os.Getenv("IPSCANNER_API_URL"),
		userAgent:  "ipscanner-go/" + Version,
		httpClient: &http.Client{},
		timeout:    defaultTimeout,
		maxRetries: defaultMaxRetries,
		backoff:    func(attempt int) time.Duration { return 500 * time.Millisecond << attempt },
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.baseURL == "" {
		c.baseURL = DefaultBaseURL
	}
	c.baseURL = strings.TrimRight(c.baseURL, "/")
	if c.httpClient == nil {
		c.httpClient = &http.Client{}
	}
	if c.maxRetries < 0 {
		c.maxRetries = 0
	}

	c.IP = &IPService{c}
	c.Bulk = &BulkService{c}
	c.Agentscan = &AgentscanService{c}
	c.Provenance = &ProvenanceService{c}
	c.Account = &AccountService{c}
	c.ASNDirectory = &ASNDirectoryService{c}
	c.Crawlers = &CrawlersService{c}
	c.Edge = &EdgeService{c}
	c.Sites = &SitesService{c}
	c.Gate = &GateService{c}
	return c
}

func escapePath(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), ":", "%3A")
}

func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	return c.doJSON(ctx, http.MethodGet, path, query, nil, out, true)
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	return c.doJSON(ctx, http.MethodPost, path, nil, body, out, true)
}

func (c *Client) postKeyless(ctx context.Context, path string, body, out any) error {
	return c.doJSON(ctx, http.MethodPost, path, nil, body, out, false)
}

func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, body, out any, auth bool) error {
	data, err := c.doRaw(ctx, method, path, query, body, "application/json", auth)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("ipscanner: decode response: %w", err)
	}
	return nil
}

func (c *Client) doRaw(ctx context.Context, method, path string, query url.Values, body any, accept string, auth bool) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok && c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	resp, err := c.send(ctx, method, path, query, body, accept, auth)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &ConnectionError{Err: err}
	}
	return data, nil
}

func (c *Client) send(ctx context.Context, method, path string, query url.Values, body any, accept string, auth bool) (*http.Response, error) {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return nil, fmt.Errorf("ipscanner: encode request: %w", err)
		}
	}

	retries := 0
	if method == http.MethodGet {
		retries = c.maxRetries
	}

	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("ipscanner: build request: %w", err)
		}
		if body == nil {
			req.Body = http.NoBody
			req.ContentLength = 0
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Accept", accept)
		req.Header.Set("User-Agent", c.userAgent)
		if auth && c.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.apiKey)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if attempt < retries && ctx.Err() == nil && c.wait(ctx, attempt) {
				continue
			}
			return nil, &ConnectionError{Err: err}
		}

		if resp.StatusCode >= 400 {
			if attempt < retries && retryableStatus(resp.StatusCode) {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if c.wait(ctx, attempt) {
					continue
				}
				return nil, &ConnectionError{Err: ctx.Err()}
			}
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, newError(resp, data)
		}
		return resp, nil
	}
}

func retryableStatus(code int) bool {
	return code == http.StatusBadGateway || code == http.StatusServiceUnavailable || code == http.StatusGatewayTimeout
}

func (c *Client) wait(ctx context.Context, attempt int) bool {
	t := time.NewTimer(c.backoff(attempt))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
