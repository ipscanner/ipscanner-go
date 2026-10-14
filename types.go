package ipscanner

import "time"

// VPNInfo is the response of GET /v1/vpn/{ip}.
type VPNInfo struct {
	IP           string   `json:"ip"`
	IsVPN        bool     `json:"isVpn"`
	IsTor        bool     `json:"isTor"`
	NetworkClass string   `json:"networkClass"`
	Anonymized   bool     `json:"anonymized"`
	Provider     string   `json:"provider"`
	VPNProvider  string   `json:"vpnProvider"`
	RiskScore    int      `json:"riskScore"`
	Evidence     []string `json:"evidence,omitempty"`
	// Purity is the score breakdown; nil when the plan locks it (DeductionCount then says how many reasons it holds).
	Purity         *Purity  `json:"purity"`
	DeductionCount *int     `json:"deductionCount,omitempty"`
	Locked         []string `json:"locked,omitempty"`
	PlanRequired   string   `json:"planRequired,omitempty"`
}

// ProxyInfo is the response of GET /v1/proxy/{ip}.
type ProxyInfo struct {
	IP           string   `json:"ip"`
	IsProxy      bool     `json:"isProxy"`
	IsTor        bool     `json:"isTor"`
	NetworkClass string   `json:"networkClass"`
	Anonymized   bool     `json:"anonymized"`
	Provider     string   `json:"provider"`
	VPNProvider  string   `json:"vpnProvider"`
	RiskScore    int      `json:"riskScore"`
	Evidence     []string `json:"evidence,omitempty"`
	// Purity is the score breakdown; nil when the plan locks it (DeductionCount then says how many reasons it holds).
	Purity         *Purity  `json:"purity"`
	DeductionCount *int     `json:"deductionCount,omitempty"`
	Locked         []string `json:"locked,omitempty"`
	PlanRequired   string   `json:"planRequired,omitempty"`
}

// Geolocation is the response of GET /v1/geo/{ip}. Locked and PlanRequired are only set on the /v1/geo body.
type Geolocation struct {
	IP             string   `json:"ip"`
	Country        string   `json:"country"`
	CountryCode    string   `json:"countryCode"`
	City           string   `json:"city"`
	Region         string   `json:"region"`
	PostalCode     string   `json:"postalCode"`
	Latitude       float64  `json:"latitude"`
	Longitude      float64  `json:"longitude"`
	Timezone       string   `json:"timezone"`
	AccuracyRadius int      `json:"accuracyRadius"`
	Locked         []string `json:"locked,omitempty"`
	PlanRequired   string   `json:"planRequired,omitempty"`
}

// ASNInfo is the response of GET /v1/asn/{ip}.
type ASNInfo struct {
	IP      string `json:"ip"`
	ASN     string `json:"asn"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Country string `json:"country"`
}

// WhoisInfo is the response of GET /v1/whois/{domain}. WhoisStatus is ok, not_found, timeout, unavailable or unparsed.
type WhoisInfo struct {
	Domain            string   `json:"domain"`
	Registrar         string   `json:"registrar"`
	RegisteredOn      string   `json:"registeredOn"`
	ExpiresOn         string   `json:"expiresOn"`
	LastUpdated       string   `json:"lastUpdated"`
	Nameservers       []string `json:"nameservers"`
	Status            []string `json:"status"`
	PrivacyProtection bool     `json:"privacyProtection"`
	WhoisStatus       string   `json:"whoisStatus,omitempty"`
}

// LookupResult is the full detection result for one target. Fields nulled by the plan are zero and listed in Locked.
type LookupResult struct {
	Target       Target       `json:"target"`
	Reserved     Reserved     `json:"reserved"`
	Verdict      Verdict      `json:"verdict"`
	Purity       Purity       `json:"purity"`
	NetworkClass string       `json:"networkClass"`
	IsVPN        bool         `json:"isVpn"`
	IsProxy      bool         `json:"isProxy"`
	IsTor        bool         `json:"isTor"`
	Provider     string       `json:"provider,omitempty"`
	VPNProvider  string       `json:"vpnProvider,omitempty"`
	RiskScore    int          `json:"riskScore"`
	NetworkType  string       `json:"networkType,omitempty"`
	Geo          *Geolocation `json:"geo,omitempty"`
	ASN          *ASNInfo     `json:"asn,omitempty"`
	Whois        *WhoisInfo   `json:"whois,omitempty"`
	WhoisStatus  string       `json:"whoisStatus,omitempty"`
	Degraded     []string     `json:"degraded,omitempty"`
	At           time.Time    `json:"at"`
	// DeductionCount is set on a locked result: how many reasons the withheld purity holds.
	DeductionCount *int     `json:"deductionCount,omitempty"`
	Locked         []string `json:"locked,omitempty"`
	PlanRequired   string   `json:"planRequired,omitempty"`
}

// Target describes what was looked up.
type Target struct {
	Raw       string `json:"raw"`
	Kind      string `json:"kind"`
	IP        string `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	Network   string `json:"network,omitempty"`
	Addresses int64  `json:"addresses,omitempty"`
}

// Reserved reports whether the address is in a reserved range.
type Reserved struct {
	Reserved bool   `json:"reserved"`
	Label    string `json:"label,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// Verdict is the network classification of an address.
type Verdict struct {
	Classification string   `json:"classification"`
	Anonymized     bool     `json:"anonymized"`
	Confidence     float64  `json:"confidence"`
	Method         string   `json:"method"`
	Evidence       []string `json:"evidence,omitempty"`
}

// Purity is the 0-100 cleanliness score and its grade.
type Purity struct {
	Score      int         `json:"score"`
	Grade      string      `json:"grade"`
	Verdict    string      `json:"verdict"`
	Deductions []Deduction `json:"deductions"`
}

// Deduction is one factor that lowered a purity score.
type Deduction struct {
	Factor string `json:"factor"`
	Points int    `json:"points"`
	Detail string `json:"detail"`
}

// Window is a daily or hourly quota window.
type Window struct {
	Limit     int64     `json:"limit"`
	Used      int64     `json:"used"`
	Remaining int64     `json:"remaining"`
	ResetAt   time.Time `json:"resetAt"`
}
