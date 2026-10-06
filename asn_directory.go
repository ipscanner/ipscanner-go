package ipscanner

import (
	"context"
	"net/url"
	"strconv"
	"strings"
)

// ASNDirectoryService browses the public autonomous system directory. No API key required.
type ASNDirectoryService struct{ c *Client }

// ASNSummary is one autonomous system in the directory.
type ASNSummary struct {
	ASN          uint32 `json:"asn"`
	Label        string `json:"label"`
	Org          string `json:"org"`
	NetworkType  string `json:"networkType"`
	IPv4Prefixes int    `json:"ipv4Prefixes"`
	IPv6Prefixes int    `json:"ipv6Prefixes"`
	Prefixes     int    `json:"prefixes"`
	Addresses    uint64 `json:"addresses"`
}

// ASNDetail is an autonomous system with sample prefixes and range counts.
type ASNDetail struct {
	ASNSummary
	SamplePrefixes          []ASNPrefix `json:"samplePrefixes"`
	VPNRangePrefixes        int         `json:"vpnRangePrefixes"`
	DatacenterRangePrefixes int         `json:"datacenterRangePrefixes"`
	RangesLoaded            bool        `json:"rangesLoaded"`
}

// ASNPrefix is one announced prefix.
type ASNPrefix struct {
	Prefix    string `json:"prefix"`
	Version   int    `json:"version"`
	Addresses uint64 `json:"addresses,omitempty"`
}

// ASNTopParams controls ASNDirectory.Top. By is "addresses" or "prefixes".
type ASNTopParams struct {
	Top int
	By  string
}

// ASNTopResult lists the largest autonomous systems.
type ASNTopResult struct {
	Total   int          `json:"total"`
	By      string       `json:"by"`
	Count   int          `json:"count"`
	Results []ASNSummary `json:"results"`
}

// ASNSearchParams controls ASNDirectory.Search.
type ASNSearchParams struct {
	Limit int
}

// ASNSearchResult lists autonomous systems matching a query.
type ASNSearchResult struct {
	Total   int          `json:"total"`
	Query   string       `json:"query"`
	Count   int          `json:"count"`
	Results []ASNSummary `json:"results"`
}

// Top lists the largest autonomous systems. params may be nil.
func (s *ASNDirectoryService) Top(ctx context.Context, params *ASNTopParams) (*ASNTopResult, error) {
	q := url.Values{}
	if params != nil {
		if params.Top > 0 {
			q.Set("top", strconv.Itoa(params.Top))
		}
		if params.By != "" {
			q.Set("by", params.By)
		}
	}
	var out ASNTopResult
	if err := s.c.get(ctx, "/v1/asn/directory", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Search finds autonomous systems by name or number. params may be nil.
func (s *ASNDirectoryService) Search(ctx context.Context, query string, params *ASNSearchParams) (*ASNSearchResult, error) {
	q := url.Values{"q": {query}}
	if params != nil && params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	var out ASNSearchResult
	if err := s.c.get(ctx, "/v1/asn/directory", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Get returns one autonomous system. asn may be "15169" or "AS15169".
func (s *ASNDirectoryService) Get(ctx context.Context, asn string) (*ASNDetail, error) {
	asn = strings.TrimSpace(asn)
	if len(asn) > 2 && strings.EqualFold(asn[:2], "AS") {
		asn = asn[2:]
	}
	var out ASNDetail
	if err := s.c.get(ctx, "/v1/asn/directory/"+escapePath(asn), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
