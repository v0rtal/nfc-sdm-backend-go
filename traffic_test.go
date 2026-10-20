package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientIPTrust(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("127.0.0.0/8")
	for _, test := range []struct {
		peer, forwarded, want string
		trust                 bool
	}{
		{"192.168.8.90:123", "8.8.8.8", "192.168.8.90", false},
		{"127.0.0.1:123", "8.8.8.8", "127.0.0.1", false},
		{"127.0.0.1:123", "8.8.8.8", "8.8.8.8", true},
		{"127.0.0.1:123", "1.1.1.1, 8.8.8.8", "8.8.8.8", true},
		{"127.0.0.1:123", "bad-value", "127.0.0.1", true},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = test.peer
		r.Header.Set("X-Forwarded-For", test.forwarded)
		recorder := &trafficRecorder{}
		if test.trust {
			recorder.trusted = []*net.IPNet{trusted}
		}
		if got := recorder.clientIP(r).String(); got != test.want {
			t.Fatalf("%+v got %s", test, got)
		}
	}
}
func TestTrafficLocationAndCache(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/8.8.8.8" {
			t.Error(r.URL.Path)
		}
		w.Write([]byte(`{"success":true,"country":"United States","region":"California","city":"Test city","latitude":37,"longitude":-122,"timezone":{"id":"America/Los_Angeles"}}`))
	}))
	defer server.Close()
	recorder := &trafficRecorder{enabled: true, endpoint: server.URL + "/", client: &http.Client{Timeout: time.Second}, cache: map[string]cachedLocation{}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.8.90:123"
	ip, location := recorder.record(context.Background(), r)
	if ip != "192.168.8.90" || !strings.Contains(string(location), "local_network") || calls != 0 {
		t.Fatalf("%s %s", ip, location)
	}
	r.RemoteAddr = "8.8.8.8:123"
	for i := 0; i < 2; i++ {
		ip, location = recorder.record(context.Background(), r)
		if ip != "8.8.8.8" || !strings.Contains(string(location), `"city":"Test city"`) {
			t.Fatalf("%s %s", ip, location)
		}
	}
	if calls != 1 {
		t.Fatal(calls)
	}
	recorder.enabled = false
	_, location = recorder.record(context.Background(), r)
	if !strings.Contains(string(location), "disabled") {
		t.Fatal(string(location))
	}
}
func TestLocationFailureIsNonfatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "rate limited", 429) }))
	defer server.Close()
	recorder := &trafficRecorder{enabled: true, endpoint: server.URL + "/", client: &http.Client{Timeout: time.Second}, cache: map[string]cachedLocation{}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "8.8.4.4:123"
	ip, location := recorder.record(context.Background(), r)
	if ip != "8.8.4.4" || !strings.Contains(string(location), "unavailable") {
		t.Fatalf("%s %s", ip, location)
	}
}

func TestCloudflareClientIP(t *testing.T) {
	t.Setenv("CLOUDFLARE_PROXY", "1")
	recorder, err := newTrafficRecorder()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		peer, header, ipv6, want string
		duplicate                bool
	}{
		{"173.245.48.12:443", "8.8.8.8", "", "8.8.8.8", false},
		{"[2606:4700::123]:443", "2001:4860:4860::8888", "", "2001:4860:4860::8888", false},
		{"192.168.8.90:443", "8.8.8.8", "", "192.168.8.90", false},
		{"8.8.4.4:443", "8.8.8.8", "", "8.8.4.4", false},
		{"173.245.48.12:443", "bad-value", "", "173.245.48.12", false},
		{"173.245.48.12:443", "8.8.8.8", "", "173.245.48.12", true},
		{"173.245.48.12:443", "240.0.0.1", "2001:4860:4860::8888", "2001:4860:4860::8888", false},
		{"173.245.48.12:443", "8.8.8.8", "2001:4860:4860::8888", "8.8.8.8", false},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = test.peer
		r.Header.Set("CF-Connecting-IP", test.header)
		r.Header.Set("CF-Connecting-IPv6", test.ipv6)
		if test.duplicate {
			r.Header.Add("CF-Connecting-IP", "1.1.1.1")
		}
		if got := recorder.clientIP(r).String(); got != test.want {
			t.Fatalf("%+v got %s", test, got)
		}
	}
	t.Setenv("CLOUDFLARE_PROXY", "0")
	disabled, err := newTrafficRecorder()
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "173.245.48.12:443"
	r.Header.Set("CF-Connecting-IP", "8.8.8.8")
	if got := disabled.clientIP(r).String(); got != "173.245.48.12" {
		t.Fatal(got)
	}
}
