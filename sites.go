package ipscanner

import (
	"context"
	"time"
)

// SitesService reads the policies of the account's sites.
type SitesService struct{ c *Client }

// SitePolicy is the policy a site enforces. Policy maps each traffic class to allow, flag or block.
type SitePolicy struct {
	Site      string            `json:"site"`
	Mode      string            `json:"mode"`
	Policy    map[string]string `json:"policy"`
	Version   int               `json:"version"`
	UpdatedAt time.Time         `json:"updatedAt"`
}

// Policy returns the current policy of a site. Not metered.
func (s *SitesService) Policy(ctx context.Context, id string) (*SitePolicy, error) {
	var out SitePolicy
	if err := s.c.get(ctx, "/v1/sites/"+escapePath(id)+"/policy", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
