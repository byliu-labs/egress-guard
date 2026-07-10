package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

func TestHTTPSender_Send_PostsExactReportJSON(t *testing.T) {
	var gotBody []byte
	var gotMethod, gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll request body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	sender := HTTPSender{Endpoint: srv.URL}
	report := NewReport("uuid-1", catalog.Identity{ExeBasename: "curl"}, "api.example.com", "allow")
	if err := sender.Send(context.Background(), report); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", gotContentType)
	}
	var got Report
	if err := json.Unmarshal(gotBody, &got); err != nil {
		t.Fatalf("Unmarshal request body: %v", err)
	}
	if got != report {
		t.Fatalf("posted report = %+v, want %+v", got, report)
	}
}

func TestHTTPSender_Send_ErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sender := HTTPSender{Endpoint: srv.URL}
	report := NewReport("uuid-1", catalog.Identity{ExeBasename: "curl"}, "api.example.com", "allow")
	if err := sender.Send(context.Background(), report); err == nil {
		t.Fatal("Send: want error on HTTP 500, got nil")
	}
}
