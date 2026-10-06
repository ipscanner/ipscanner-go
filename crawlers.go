package ipscanner

import "context"

// CrawlersService lists the crawlers that can be verified. No API key required.
type CrawlersService struct{ c *Client }

// CrawlerList is the crawler catalogue.
type CrawlerList struct {
	Crawlers []Crawler `json:"crawlers"`
	Count    int       `json:"count"`
	Note     string    `json:"note"`
}

// Crawler is one verifiable crawler and the evidence it is checked against.
type Crawler struct {
	Slug        string   `json:"slug"`
	Name        string   `json:"name"`
	Tokens      []string `json:"tokens"`
	Method      string   `json:"method"`
	Verifiable  bool     `json:"verifiable"`
	ReverseDNS  []string `json:"reverseDns,omitempty"`
	PrefixFiles []string `json:"prefixFiles,omitempty"`
	ASNs        []int    `json:"asns,omitempty"`
	Docs        string   `json:"docs,omitempty"`
	Note        string   `json:"note,omitempty"`
}

// List returns the crawler catalogue.
func (s *CrawlersService) List(ctx context.Context) (*CrawlerList, error) {
	var out CrawlerList
	if err := s.c.get(ctx, "/v1/crawlers", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
