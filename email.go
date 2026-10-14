package ipscanner

import "context"

// EmailService checks email addresses.
type EmailService struct{ c *Client }

// EmailCheck is the response of POST /v1/email/check. Status is valid, invalid, risky or unknown;
// Reason and Suggestion are empty when the API sends null.
type EmailCheck struct {
	Email      string      `json:"email"`
	Status     string      `json:"status"`
	Reason     string      `json:"reason"`
	Suggestion string      `json:"suggestion"`
	Domain     string      `json:"domain"`
	Checks     EmailChecks `json:"checks"`
	Mailbox    string      `json:"mailbox"`
}

// EmailChecks are the checks behind an email status. MX is nil when DNS was not asked or did not answer.
type EmailChecks struct {
	Syntax       bool  `json:"syntax"`
	MX           *bool `json:"mx"`
	Disposable   bool  `json:"disposable"`
	Role         bool  `json:"role"`
	FreeProvider bool  `json:"freeProvider"`
}

// Check checks one email address: syntax, throwaway domains, mail servers, typos and role addresses.
func (s *EmailService) Check(ctx context.Context, email string) (*EmailCheck, error) {
	var out EmailCheck
	if err := s.c.post(ctx, "/v1/email/check", map[string]string{"email": email}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
