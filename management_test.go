package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"image"
	"image/png"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/v0rtal/nfc-sdm-backend-go/inventory"
	"github.com/v0rtal/nfc-sdm-backend-go/sdm"
)

func TestImageValidation(t *testing.T) {
	if _, _, err := sanitizeImage([]byte(`<svg onload="alert(1)"></svg>`)); err == nil {
		t.Fatal("SVG accepted")
	}
	var data bytes.Buffer
	png.Encode(&data, image.NewRGBA(image.Rect(0, 0, 4, 4)))
	clean, mime, err := sanitizeImage(data.Bytes())
	if err != nil || len(clean) == 0 || mime != "image/png" {
		t.Fatalf("%s %v", mime, err)
	}
}
func TestInventoryHTTP(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL")
	}
	store, err := isolatedInventory(t, url)
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	// Fixture UID belongs to the factory-key upstream vector; test database only.
	uid := "04DE5F1EACC040"
	defer func() {
		for _, table := range []string{"item_images", "scan_events", "scans", "tags"} {
			store.DB.Exec(context.Background(), "DELETE FROM "+table+" WHERE uid=$1", uid)
		}
	}()
	for _, table := range []string{"item_images", "scan_events", "scans", "tags"} {
		if _, err = store.DB.Exec(context.Background(), "DELETE FROM "+table+" WHERE uid=$1", uid); err != nil {
			t.Fatal(err)
		}
	}
	token := strings.Repeat("a", 64)
	h := handlerWithBackend(sdm.Verifier{Master: make([]byte, 16), DeriveMode: "legacy", MACParam: "cmac"}, &backend{store: store, adminToken: token, traffic: &trafficRecorder{enabled: false}})
	request := func(method, path string, body []byte, auth bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.TLS = &tls.ConnectionState{}
		if auth {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	path := "/api/tag?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086"
	first := request("GET", path, nil, false)
	if first.Code != 200 {
		t.Fatal(first.Body.String())
	}
	var response struct {
		LinkValid bool `json:"link_valid"`
	}
	json.Unmarshal(first.Body.Bytes(), &response)
	if !response.LinkValid {
		t.Fatal(first.Body.String())
	}
	repeat := request("GET", path, nil, false)
	if !strings.Contains(repeat.Body.String(), `"status":"replayed"`) {
		t.Fatal(repeat.Body.String())
	}
	invalid := request("GET", "/api/tag?picc_data=EF963FF7828658A599F3041510671E88&cmac=0000000000000000", nil, false)
	if invalid.Code != 400 {
		t.Fatal(invalid.Code)
	}
	tag, err := store.Get(context.Background(), uid)
	if err != nil || tag.RequestCount != 2 {
		t.Fatalf("%+v %v", tag, err)
	}
	events, eventErr := store.History(context.Background(), uid)
	if eventErr != nil || len(events) != 2 || events[0].ClientIP != "192.0.2.1" || !strings.Contains(string(events[0].Location), "disabled") || events[0].ViewedAt.IsZero() {
		t.Fatalf("history=%+v error=%v", events, eventErr)
	}
	if got := request("GET", "/api/admin/tags", nil, false); got.Code != 401 {
		t.Fatal(got.Code)
	}
	item := []byte(`{"name":"<script>alert(1)</script>","description":"A tagged item","attributes":{"serial":"123"}}`)
	if got := request("PUT", "/api/admin/tags/"+uid, item, true); got.Code != 200 {
		t.Fatal(got.Code, got.Body.String())
	}
	var imageBytes bytes.Buffer
	png.Encode(&imageBytes, image.NewRGBA(image.Rect(0, 0, 2, 2)))
	uploaded := request("POST", "/api/admin/tags/"+uid+"/images", imageBytes.Bytes(), true)
	if uploaded.Code != 201 {
		t.Fatal(uploaded.Code, uploaded.Body.String())
	}
	var photo inventory.Image
	json.Unmarshal(uploaded.Body.Bytes(), &photo)
	if got := request("GET", photo.URL, nil, false); got.Code != 200 || got.Header().Get("Content-Type") != "image/png" {
		t.Fatal(got.Code)
	}
	page := request("GET", strings.Replace(path, "/api/tag", "/tagtt", 1), nil, false)
	if strings.Contains(page.Body.String(), "<script>alert(1)</script>") || !strings.Contains(page.Body.String(), "&lt;script&gt;") {
		t.Fatal("Item HTML was not escaped")
	}
	if !strings.Contains(page.Body.String(), "Last 10 scan openings") || strings.Contains(page.Body.String(), "Verified tag message") || strings.Contains(page.Body.String(), "192.0.2.1") || !strings.Contains(page.Body.String(), "replayed") {
		t.Fatal("Public TagTamper history content incorrect: ", page.Body.String())
	}
	for _, path := range []string{"/", "/items/" + uid} {
		directory := request("GET", path, nil, false)
		if directory.Code != 200 || !strings.Contains(directory.Body.String(), uid) || !strings.Contains(directory.Body.String(), "A tagged item") || strings.Contains(directory.Body.String(), "192.0.2.1") || strings.Contains(directory.Body.String(), "<script>alert(1)</script>") {
			t.Fatal("Directory content incorrect: ", directory.Body.String())
		}
	}
	afterDirectory, e := store.Get(context.Background(), uid)
	if e != nil || afterDirectory.RequestCount != 3 {
		t.Fatal("Directory browsing registered scan events", e)
	}
	if got := request("DELETE", "/api/admin/tags/"+uid+"/images/"+photo.ID, nil, true); got.Code != 204 {
		t.Fatal(got.Code)
	}
	r := httptest.NewRequest("GET", "/api/admin/tags", nil)
	r.RemoteAddr = "192.168.8.90:1234"
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("Nonlocal HTTP administration allowed")
	}
}
