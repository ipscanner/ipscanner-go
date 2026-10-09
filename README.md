# ipscanner-go

The official Go client for the [IPScanner](https://ipscanner.io) API.

Full API reference: https://ipscanner.io/api-documentation

## Install

```sh
go get github.com/ipscanner/ipscanner-go
```

Requires Go 1.23 or later. No dependencies outside the standard library.

## Quick start

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/ipscanner/ipscanner-go"
)

func main() {
	client := ipscanner.NewClient(ipscanner.WithAPIKey("pk_live_..."))

	res, err := client.IP.Lookup(context.Background(), "1.1.1.1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res.NetworkClass, res.Purity.Grade, res.Verdict.Confidence)
}
```

## Usage

Every method takes a `context.Context` first.

### IP

```go
res, err := client.IP.Lookup(ctx, "8.8.8.8")    // IPv4, IPv6, CIDR or hostname
vpn, err := client.IP.VPN(ctx, "2001:db8::1")
proxy, err := client.IP.Proxy(ctx, "1.2.3.4")
geo, err := client.IP.Geo(ctx, "1.2.3.4")
asn, err := client.IP.ASN(ctx, "1.2.3.4")
whois, err := client.IP.Whois(ctx, "example.com")
hist, err := client.IP.History(ctx, &ipscanner.HistoryParams{Limit: 50})
demo, err := client.IP.Demo(ctx, "1.2.3.4") // no key required
me, err := client.IP.MyIP(ctx)              // no key required
```

`VPNProvider` is the VPN brand (for example Mullvad) when known; `Provider` is the network owner.

On the Free plan premium fields (purity, provider, VPN brand, precise location) come back as JSON null, so they decode as zero values, and are listed in `Locked` with `PlanRequired`.

### Bulk

```go
out, err := client.Bulk.Check(ctx, ipscanner.BulkParams{IPs: []string{"1.1.1.1", "8.8.8.8"}})

for ev, err := range client.Bulk.Stream(ctx, ipscanner.BulkParams{Input: pasted}) {
	if err != nil {
		log.Fatal(err)
	}
	switch ev.Type {
	case "result":
		fmt.Println(ev.Index, ev.IP, ev.Grade)
	case "error":
		fmt.Println(ev.Index, ev.Input, ev.Reason)
	case "done":
		fmt.Println("complete:", ev.Complete())
	}
}
```

`Stream` reads the NDJSON response line by line. It uses a 5 minute timeout unless the context already has a deadline. `Complete()` is false when the run stopped early (quota or server deadline).

### Agentscan

```go
v, err := client.Agentscan.Check(ctx, ipscanner.AgentscanCheckParams{
	IP:        "1.2.3.4",
	UserAgent: r.UserAgent(),
	Headers:   map[string]string{"accept-language": "en"},
})

batch, err := client.Agentscan.Batch(ctx, []ipscanner.AgentscanBatchLine{{Line: 1, IP: "1.2.3.4", UserAgent: "GPTBot/1.0"}})
check, err := client.Agentscan.Verify(ctx, ipscanner.AgentscanVerifyParams{IP: "66.249.66.1", UserAgent: "Googlebot"})
agents, err := client.Agentscan.Allowlist(ctx)
self, err := client.Agentscan.SelfCheck(ctx, nil)
```

### Edge and sites

```go
res, err := client.Edge.Check(ctx, ipscanner.EdgeCheckParams{
	IP:        "1.2.3.4",
	Site:      "site_...",
	UserAgent: r.UserAgent(),
})
fmt.Println(res.Class, res.Site != nil)

policy, err := client.Sites.Policy(ctx, "site_...")
```

`Edge.Check` is metered as 2 requests. `Sites.Policy` is not metered.

### Gate

Runs on your server. Sends no API key; the site secret is the credential. Never retried.

```go
v, err := client.Gate.Verify(ctx, ipscanner.GateVerifyParams{
	Secret:   "gs_...",
	Token:    token, // the token gate.js added to the form
	RemoteIP: clientIP,
})
if err == nil && v.Action != "block" {
	// accept the form
}
```

### Provenance

```go
att, err := client.Provenance.Check(ctx, ipscanner.ProvenanceCheckParams{IP: "1.2.3.4", ClaimedJurisdiction: "uk"})
ok, err := client.Provenance.Verify(ctx)
anchored, err := client.Provenance.VerifyAnchored(ctx)
page, err := client.Provenance.Chain(ctx, &ipscanner.ChainParams{Limit: 100})
list, err := client.Provenance.Jurisdictions(ctx)
csv, err := client.Provenance.Export(ctx, &ipscanner.ExportParams{From: "2026-10-01", To: "2026-10-31"})
```

### Account

```go
limits, err := client.Account.Limits(ctx)
usage, err := client.Account.Usage(ctx)
```

### ASN directory

No key required.

```go
top, err := client.ASNDirectory.Top(ctx, &ipscanner.ASNTopParams{Top: 20, By: "addresses"})
found, err := client.ASNDirectory.Search(ctx, "cloudflare", nil)
detail, err := client.ASNDirectory.Get(ctx, "AS15169")
```

### Crawlers

No key required.

```go
list, err := client.Crawlers.List(ctx)
```

## Errors

Non-2xx responses return `*ipscanner.APIError` with `Status`, `Code`, `Message`, `Details` and the raw `Body`. A 429 returns `*ipscanner.RateLimitError`, which also matches `*APIError` with `errors.As`.

```go
res, err := client.IP.Lookup(ctx, "1.1.1.1")

var rl *ipscanner.RateLimitError
var apiErr *ipscanner.APIError
switch {
case errors.As(err, &rl):
	fmt.Println(rl.Reason, rl.RetryAfter, rl.Remaining, rl.UpgradeURL)
case ipscanner.IsAuth(err):
	// 401 or 403
case ipscanner.IsNotFound(err):
	// 404
case errors.As(err, &apiErr):
	fmt.Println(apiErr.Status, apiErr.Code, apiErr.Message)
}
```

Network failures and timeouts return `*ipscanner.ConnectionError`. GET requests are retried up to 2 times on network errors and 502, 503 or 504 responses. POST requests and 429 responses are never retried.

## Configuration

```go
client := ipscanner.NewClient(
	ipscanner.WithAPIKey("pk_live_..."),           // default: IPSCANNER_API_KEY
	ipscanner.WithBaseURL("https://ipscanner.io"), // default: IPSCANNER_API_URL or https://ipscanner.io
	ipscanner.WithTimeout(30*time.Second),         // per request, when ctx has no deadline
	ipscanner.WithMaxRetries(2),
	ipscanner.WithHTTPClient(&http.Client{}),
	ipscanner.WithUserAgent("my-app/1.0"),
)
```

## Licence

MIT
