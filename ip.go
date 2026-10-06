package ipscanner

import (
	"context"
	"net/url"
	"strconv"
	"time"
)

// IPService covers single-address detection endpoints.
type IPService struct{ c *Client }

// HistoryParams filters IP.History. Zero values are omitted.
type HistoryParams struct {
	Limit   int
	Before  int64
	Verdict string
}

// History is a page of past lookups.
type History struct {
	Events     []HistoryEvent `json:"events"`
	NextBefore int64          `json:"nextBefore"`
	AsOf       time.Time      `json:"asOf"`
}

// HistoryEvent is one past lookup.
type HistoryEvent struct {
	ID         int64     `json:"id"`
	At         time.Time `json:"at"`
	Target     string    `json:"target"`
	IP         string    `json:"ip"`
	Verdict    string    `json:"verdict"`
	Confidence float64   `json:"confidence"`
	ASN        string    `json:"asn"`
	ASNName    string    `json:"asnName"`
	Country    string    `json:"country"`
	Anonymized bool      `json:"anonymized"`
	Source     string    `json:"source"`
}

// MyIP is the caller's own address with location and network.
type MyIP struct {
	IPv4           string  `json:"ipv4,omitempty"`
	IPv6           string  `json:"ipv6,omitempty"`
	Country        string  `json:"country"`
	CountryCode    string  `json:"countryCode"`
	City           string  `json:"city"`
	Region         string  `json:"region"`
	PostalCode     string  `json:"postalCode"`
	Latitude       float64 `json:"latitude"`
	Longitude      float64 `json:"longitude"`
	Timezone       string  `json:"timezone"`
	AccuracyRadius int     `json:"accuracyRadius"`
	ASN            string  `json:"asn"`
	ASNName        string  `json:"asnName"`
	ASNType        string  `json:"asnType"`
	ASNCountry     string  `json:"asnCountry"`
}

// Lookup runs a full detection on an IPv4, IPv6, CIDR or hostname target.
func (s *IPService) Lookup(ctx context.Context, target string) (*LookupResult, error) {
	var out LookupResult
	body := struct {
		Target string `json:"target"`
	}{target}
	if err := s.c.post(ctx, "/v1/ip/lookup", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VPN reports whether an address is a VPN or Tor exit.
func (s *IPService) VPN(ctx context.Context, ip string) (*VPNInfo, error) {
	var out VPNInfo
	if err := s.c.get(ctx, "/v1/vpn/"+escapePath(ip), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Proxy reports whether an address is a proxy.
func (s *IPService) Proxy(ctx context.Context, ip string) (*ProxyInfo, error) {
	var out ProxyInfo
	if err := s.c.get(ctx, "/v1/proxy/"+escapePath(ip), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Geo returns the location of an address.
func (s *IPService) Geo(ctx context.Context, ip string) (*Geolocation, error) {
	var out Geolocation
	if err := s.c.get(ctx, "/v1/geo/"+escapePath(ip), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ASN returns the autonomous system of an address.
func (s *IPService) ASN(ctx context.Context, ip string) (*ASNInfo, error) {
	var out ASNInfo
	if err := s.c.get(ctx, "/v1/asn/"+escapePath(ip), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Whois returns registration data for a domain.
func (s *IPService) Whois(ctx context.Context, domain string) (*WhoisInfo, error) {
	var out WhoisInfo
	if err := s.c.get(ctx, "/v1/whois/"+escapePath(domain), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// History lists the account's recent lookups. params may be nil.
func (s *IPService) History(ctx context.Context, params *HistoryParams) (*History, error) {
	q := url.Values{}
	if params != nil {
		if params.Limit > 0 {
			q.Set("limit", strconv.Itoa(params.Limit))
		}
		if params.Before > 0 {
			q.Set("before", strconv.FormatInt(params.Before, 10))
		}
		if params.Verdict != "" {
			q.Set("verdict", params.Verdict)
		}
	}
	var out History
	if err := s.c.get(ctx, "/v1/ip/history", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Demo runs a keyless, rate-limited lookup.
func (s *IPService) Demo(ctx context.Context, ip string) (*LookupResult, error) {
	var out LookupResult
	if err := s.c.get(ctx, "/v1/demo/"+escapePath(ip), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MyIP returns the caller's own address. No API key required.
func (s *IPService) MyIP(ctx context.Context) (*MyIP, error) {
	var out MyIP
	if err := s.c.get(ctx, "/v1/myip", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
