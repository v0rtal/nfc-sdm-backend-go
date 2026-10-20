package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type trafficRecorder struct {
	trusted    []*net.IPNet
	cloudflare []*net.IPNet
	enabled    bool
	endpoint   string
	client     *http.Client
	mu         sync.Mutex
	cache      map[string]cachedLocation
}

//go:embed cloudflare-cidrs.txt
var cloudflareCIDRs string

type cachedLocation struct {
	value   json.RawMessage
	expires time.Time
}

func newTrafficRecorder() (*trafficRecorder, error) {
	// Third-party IP disclosure is opt-in for a new deployment.
	t := &trafficRecorder{enabled: env("IP_GEOLOCATION", "0") == "1", endpoint: "https://ipwho.is/", client: &http.Client{Timeout: 1500 * time.Millisecond}, cache: map[string]cachedLocation{}}
	if env("CLOUDFLARE_PROXY", "0") == "1" {
		for _, cidr := range strings.Fields(cloudflareCIDRs) {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, err
			}
			t.cloudflare = append(t.cloudflare, network)
		}
	}
	for _, cidr := range strings.Split(env("TRUSTED_PROXY_CIDRS", ""), ",") {
		if strings.TrimSpace(cidr) == "" {
			continue
		}
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("invalid TRUSTED_PROXY_CIDRS entry: %s", cidr)
		}
		t.trusted = append(t.trusted, network)
	}
	return t, nil
}
func (t *trafficRecorder) trusts(ip net.IP) bool {
	for _, network := range t.trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
func (t *trafficRecorder) clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	peer := net.ParseIP(host)
	for _, network := range t.cloudflare {
		if network.Contains(peer) {
			values := r.Header.Values("CF-Connecting-IP")
			if len(values) != 1 {
				return peer
			}
			visitor := net.ParseIP(strings.TrimSpace(values[0]))
			if visitor == nil {
				return peer
			}
			// Cloudflare Pseudo IPv4 Overwrite mode preserves the real IPv6 here.
			if v4 := visitor.To4(); v4 != nil && v4[0] >= 240 {
				ipv6Values := r.Header.Values("CF-Connecting-IPv6")
				if len(ipv6Values) == 1 {
					if ipv6 := net.ParseIP(strings.TrimSpace(ipv6Values[0])); ipv6 != nil && ipv6.To4() == nil {
						return ipv6
					}
				}
			}
			return visitor
		}
	}
	if peer == nil || !t.trusts(peer) {
		return peer
	}
	chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	if len(chain) > 20 {
		return peer
	}
	current := peer
	for i := len(chain) - 1; i >= 0; i-- {
		if !t.trusts(current) {
			break
		}
		ip := net.ParseIP(strings.TrimSpace(chain[i]))
		if ip == nil {
			return peer
		}
		current = ip
	}
	return current
}
func (t *trafficRecorder) record(ctx context.Context, r *http.Request) (string, json.RawMessage) {
	ip := t.clientIP(r)
	if ip == nil {
		return "", json.RawMessage(`{"status":"unknown"}`)
	}
	address := ip.String()
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || !ip.IsGlobalUnicast() {
		return address, json.RawMessage(`{"status":"local_network","source":"request_ip"}`)
	}
	// Shared carrier NAT addresses are not publicly geolocatable.
	_, carrier, _ := net.ParseCIDR("100.64.0.0/10")
	if carrier.Contains(ip) {
		return address, json.RawMessage(`{"status":"local_network","source":"request_ip"}`)
	}
	if !t.enabled {
		return address, json.RawMessage(`{"status":"disabled","source":"request_ip"}`)
	}
	t.mu.Lock()
	cached, found := t.cache[address]
	t.mu.Unlock()
	if found && time.Now().Before(cached.expires) {
		return address, cached.value
	}
	value := json.RawMessage(`{"status":"unavailable","source":"ipwho.is","approximate":true}`)
	req, err := http.NewRequestWithContext(ctx, "GET", t.endpoint+address, nil)
	if err == nil {
		response, e := t.client.Do(req)
		if e == nil {
			defer response.Body.Close()
			var result struct {
				Success   bool     `json:"success"`
				Country   string   `json:"country"`
				Region    string   `json:"region"`
				City      string   `json:"city"`
				Latitude  *float64 `json:"latitude"`
				Longitude *float64 `json:"longitude"`
				Timezone  struct {
					ID string `json:"id"`
				} `json:"timezone"`
			}
			if response.StatusCode == 200 && json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&result) == nil && result.Success {
				if result.Latitude != nil && (*result.Latitude < -90 || *result.Latitude > 90) {
					result.Latitude = nil
				}
				if result.Longitude != nil && (*result.Longitude < -180 || *result.Longitude > 180) {
					result.Longitude = nil
				}
				value, _ = json.Marshal(map[string]any{"status": "located", "source": "ipwho.is", "approximate": true, "country": result.Country, "region": result.Region, "city": result.City, "latitude": result.Latitude, "longitude": result.Longitude, "timezone": result.Timezone.ID})
			}
		}
	}
	ttl := 10 * time.Minute
	if strings.Contains(string(value), `"located"`) {
		ttl = 24 * time.Hour
	}
	t.mu.Lock()
	if len(t.cache) >= 4096 {
		t.cache = map[string]cachedLocation{}
	}
	t.cache[address] = cachedLocation{value: value, expires: time.Now().Add(ttl)}
	t.mu.Unlock()
	return address, value
}
