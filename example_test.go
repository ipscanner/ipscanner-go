package ipscanner_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/ipscanner/ipscanner-go"
)

func fakeAPI() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/ip/lookup":
			io.WriteString(w, `{"target":{"raw":"1.1.1.1","kind":"ipv4","ip":"1.1.1.1"},"networkClass":"hosting",
				"purity":{"score":70,"grade":"B","verdict":"suspect"},"at":"2026-10-06T12:00:00Z"}`)
		case "/v1/ip/bulk":
			io.WriteString(w, `{"type":"meta","total":2}
{"type":"result","ip":"1.1.1.1","grade":"B"}
{"type":"result","index":1,"ip":"8.8.8.8","grade":"A"}
{"type":"done","reason":"complete","total":2,"processed":2}
`)
		case "/v1/user/limits":
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"error":"rate_limit_exceeded","reason":"monthly_quota","message":"Allowance used.","retryAfter":3600}`)
		}
	}))
}

func ExampleIPService_Lookup() {
	srv := fakeAPI()
	defer srv.Close()

	client := ipscanner.NewClient(ipscanner.WithAPIKey("pk_live_..."), ipscanner.WithBaseURL(srv.URL))
	res, err := client.IP.Lookup(context.Background(), "1.1.1.1")
	if err != nil {
		panic(err)
	}
	fmt.Println(res.Target.IP, res.NetworkClass, res.Purity.Grade)
	// Output: 1.1.1.1 hosting B
}

func ExampleBulkService_Stream() {
	srv := fakeAPI()
	defer srv.Close()

	client := ipscanner.NewClient(ipscanner.WithAPIKey("pk_live_..."), ipscanner.WithBaseURL(srv.URL))
	for ev, err := range client.Bulk.Stream(context.Background(), ipscanner.BulkParams{IPs: []string{"1.1.1.1", "8.8.8.8"}}) {
		if err != nil {
			panic(err)
		}
		switch ev.Type {
		case "result":
			fmt.Println(ev.Index, ev.IP, ev.Grade)
		case "done":
			fmt.Println("complete:", ev.Complete())
		}
	}
	// Output:
	// 0 1.1.1.1 B
	// 1 8.8.8.8 A
	// complete: true
}

func ExampleRateLimitError() {
	srv := fakeAPI()
	defer srv.Close()

	client := ipscanner.NewClient(ipscanner.WithAPIKey("pk_live_..."), ipscanner.WithBaseURL(srv.URL))
	_, err := client.Account.Limits(context.Background())

	var rl *ipscanner.RateLimitError
	if errors.As(err, &rl) {
		fmt.Println(rl.Reason, rl.RetryAfter)
	}
	// Output: monthly_quota 1h0m0s
}
