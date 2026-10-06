package ipscanner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

const ndjson = `{"type":"meta","total":3,"processed":1,"failed":1,"metered":3}
{"type":"result","ip":"1.1.1.1","verdict":"suspect","classification":"hosting","confidence":0.9,"score":70,"grade":"B","asn":"AS13335"}
{"type":"error","index":1,"input":"10.0.0.1","ip":"10.0.0.1","reason":"reserved","message":"Private network","error":"Private network"}

{"type":"result","index":2,"ip":"81.214.3.44","verdict":"clean","classification":"residential_clean","grade":"S","score":100}
{"type":"done","reason":"complete","total":3,"processed":2,"failed":1}
`

func TestStream(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/ip/bulk" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Accept"); got != "application/x-ndjson" {
			t.Errorf("Accept = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"ips":["1.1.1.1","10.0.0.1","81.214.3.44"]}` {
			t.Errorf("body = %s", body)
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		io.WriteString(w, ndjson)
	})

	var events []*BulkEvent
	for ev, err := range c.Bulk.Stream(context.Background(), BulkParams{IPs: []string{"1.1.1.1", "10.0.0.1", "81.214.3.44"}}) {
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, ev)
	}
	if len(events) != 5 {
		t.Fatalf("got %d events", len(events))
	}
	meta, first, failed, clean, done := events[0], events[1], events[2], events[3], events[4]
	if meta.Type != "meta" || meta.Total != 3 || meta.Processed != 1 || meta.Metered != 3 {
		t.Errorf("meta = %+v", meta)
	}
	if first.Type != "result" || first.Index != 0 || first.IP != "1.1.1.1" || first.Anonymized || first.IsTorExit {
		t.Errorf("first = %+v", first)
	}
	if failed.Type != "error" || failed.Index != 1 || failed.Reason != "reserved" {
		t.Errorf("error = %+v", failed)
	}
	if clean.Index != 2 || clean.Confidence != 0 || clean.ASN != "" || clean.Score != 100 {
		t.Errorf("clean = %+v", clean)
	}
	if !done.Complete() {
		t.Errorf("done should be complete: %+v", done)
	}
	if meta.Complete() {
		t.Errorf("meta should not be complete")
	}
}

func TestStreamIncompleteDone(t *testing.T) {
	for _, line := range []string{
		`{"type":"done","reason":"complete","total":5,"processed":2,"failed":1}`,
		`{"type":"done","reason":"quota_exceeded","total":5,"processed":5,"message":"Monthly allowance reached."}`,
	} {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"type":"meta","total":5}`+"\n"+line+"\n")
		})
		var last *BulkEvent
		for ev, err := range c.Bulk.Stream(context.Background(), BulkParams{IPs: []string{"1.1.1.1"}}) {
			if err != nil {
				t.Fatal(err)
			}
			last = ev
		}
		if last.Type != "done" || last.Complete() {
			t.Errorf("Complete() should be false for %s", line)
		}
	}
}

func TestStreamTruncated(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"type":"meta","total":2}`+"\n"+`{"type":"result","ip":"1.1.1.1"}`+"\n")
	})
	var n int
	var gotErr error
	for ev, err := range c.Bulk.Stream(context.Background(), BulkParams{IPs: []string{"1.1.1.1"}}) {
		if err != nil {
			gotErr = err
			break
		}
		if ev != nil {
			n++
		}
	}
	if n != 2 || !errors.Is(gotErr, io.ErrUnexpectedEOF) {
		t.Errorf("n = %d err = %v", n, gotErr)
	}
}

func TestStreamEarlyBreak(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, ndjson)
	})
	n := 0
	for _, err := range c.Bulk.Stream(context.Background(), BulkParams{IPs: []string{"1.1.1.1"}}) {
		if err != nil {
			t.Fatal(err)
		}
		n++
		if n == 2 {
			break
		}
	}
	if n != 2 {
		t.Errorf("n = %d", n)
	}
}

func TestStreamPreStreamError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 429, map[string]any{"error": "rate_limit_exceeded", "reason": "monthly_quota", "message": "spent", "retryAfter": 60})
	})
	var gotErr error
	for ev, err := range c.Bulk.Stream(context.Background(), BulkParams{Input: "1.1.1.1"}) {
		if ev != nil {
			t.Errorf("unexpected event %+v", ev)
		}
		gotErr = err
	}
	var rl *RateLimitError
	if !errors.As(gotErr, &rl) || rl.Reason != "monthly_quota" {
		t.Errorf("err = %v", gotErr)
	}
}

func TestStreamLongLine(t *testing.T) {
	long := make([]byte, 200*1024)
	for i := range long {
		long[i] = 'a'
	}
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"type":"error","input":"`+string(long)+`"}`+"\n"+`{"type":"done","reason":"complete","failed":1,"total":1}`+"\n")
	})
	var events []*BulkEvent
	for ev, err := range c.Bulk.Stream(context.Background(), BulkParams{Input: "x"}) {
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, ev)
	}
	if len(events) != 2 || len(events[0].Input) != len(long) || !events[1].Complete() {
		t.Errorf("unexpected events")
	}
}
