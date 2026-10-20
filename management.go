package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/v0rtal/nfc-sdm-backend-go/inventory"
)

type backend struct {
	store      *inventory.Store
	adminToken string
	traffic    *trafficRecorder
}

// Public history deliberately excludes request IPs and location data.
type publicScanEvent struct {
	ViewedAt     time.Time
	Counter      *uint32
	Status       string
	TamperStatus string
}

func tamperBadge(status string, verified bool) (string, string) {
	if !verified {
		return "Tamper: Unknown", "badge-neutral"
	}
	switch status {
	case "secure":
		return "Tamper: Good", "badge-green"
	case "tampered_closed", "tampered_open":
		return "Tamper: Tampered", "badge-red"
	case "not_initialized":
		return "Tamper: Not initialized", "badge-neutral"
	case "not_supported":
		return "Tamper: Not supported", "badge-neutral"
	default:
		return "Tamper: Unknown", "badge-neutral"
	}
}

var uidPattern = regexp.MustCompile(`^[0-9A-F]{14}$`)
var imagePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func sendJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func dbError(w http.ResponseWriter, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "not found", 404)
	} else {
		log.Printf("Database request failed: %v", err)
		http.Error(w, "Database unavailable; try again later", 503)
	}
}
func (b *backend) routes(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/admin" {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return true
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, adminPage)
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/images/") {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return true
		}
		if b.store == nil {
			http.Error(w, "Database not configured", 503)
			return true
		}
		id := strings.TrimPrefix(r.URL.Path, "/images/")
		if !imagePattern.MatchString(id) {
			http.NotFound(w, r)
			return true
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		var mime string
		var data []byte
		err := b.store.DB.QueryRow(ctx, "SELECT mime,data FROM item_images WHERE id=$1", id).Scan(&mime, &data)
		if err != nil {
			dbError(w, err)
			return true
		}
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Write(data)
		return true
	}
	if !strings.HasPrefix(r.URL.Path, "/api/admin/") {
		return false
	}
	if b.store == nil || b.adminToken == "" {
		http.Error(w, "Inventory management is not configured", 503)
		return true
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if r.TLS == nil && (ip == nil || !ip.IsLoopback()) {
		http.Error(w, "Use HTTPS for management", 403)
		return true
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare([]byte(token), []byte(b.adminToken)) != 1 {
		http.Error(w, "Invalid management password", 401)
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/")
	parts := strings.Split(path, "/")
	if path == "tags" && r.Method == "GET" {
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		if offset < 0 {
			offset = 0
		}
		tags, err := b.store.List(ctx, 100, offset)
		if err != nil {
			dbError(w, err)
		} else {
			sendJSON(w, 200, tags)
		}
		return true
	}
	if len(parts) < 2 || parts[0] != "tags" || !uidPattern.MatchString(parts[1]) {
		http.NotFound(w, r)
		return true
	}
	uid := parts[1]
	if len(parts) == 2 {
		switch r.Method {
		case "GET":
			tag, err := b.store.Get(ctx, uid)
			if err != nil {
				dbError(w, err)
			} else {
				sendJSON(w, 200, tag)
			}
		case "PUT":
			var item struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				Attributes  json.RawMessage `json:"attributes"`
			}
			r.Body = http.MaxBytesReader(w, r.Body, 65536)
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&item); err != nil {
				http.Error(w, "Invalid item JSON", 400)
				return true
			}
			var extra any
			if err := decoder.Decode(&extra); err != io.EOF {
				http.Error(w, "Use one JSON object", 400)
				return true
			}
			if len(item.Name) > 200 || len(item.Description) > 10000 {
				http.Error(w, "Item text too long", 400)
				return true
			}
			if len(item.Attributes) == 0 {
				item.Attributes = json.RawMessage(`{}`)
			}
			var attrs map[string]any
			if json.Unmarshal(item.Attributes, &attrs) != nil || attrs == nil {
				http.Error(w, "Attributes must be a JSON object", 400)
				return true
			}
			if err := b.store.Update(ctx, uid, item.Name, item.Description, item.Attributes); err != nil {
				dbError(w, err)
			} else {
				sendJSON(w, 200, map[string]bool{"saved": true})
			}
		default:
			w.Header().Set("Allow", "GET, PUT")
			http.Error(w, "method not allowed", 405)
		}
		return true
	}
	if len(parts) == 3 && parts[2] == "history" && r.Method == "GET" {
		events, err := b.store.History(ctx, uid)
		if err != nil {
			dbError(w, err)
		} else {
			sendJSON(w, 200, events)
		}
		return true
	}
	if len(parts) == 3 && parts[2] == "images" && r.Method == "POST" {
		r.Body = http.MaxBytesReader(w, r.Body, 5*1024*1024)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Image must be at most 5 MiB", 413)
			return true
		}
		data, mime, err := sanitizeImage(raw)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return true
		}
		id := make([]byte, 16)
		if _, err = rand.Read(id); err != nil {
			http.Error(w, "Cannot generate image ID", 500)
			return true
		}
		idHex := hex.EncodeToString(id)
		if err = b.store.SaveImage(ctx, idHex, uid, mime, data); err != nil {
			if err.Error() == "image limit reached" {
				http.Error(w, "At most 10 images per tag", 400)
			} else {
				dbError(w, err)
			}
		} else {
			sendJSON(w, 201, inventory.Image{ID: idHex, URL: "/images/" + idHex})
		}
		return true
	}
	if len(parts) == 4 && parts[2] == "images" && imagePattern.MatchString(parts[3]) && r.Method == "DELETE" {
		result, err := b.store.DB.Exec(ctx, `DELETE FROM item_images WHERE uid=$1 AND id=$2`, uid, parts[3])
		if err != nil {
			dbError(w, err)
		} else if result.RowsAffected() == 0 {
			http.NotFound(w, r)
		} else {
			w.WriteHeader(204)
		}
		return true
	}
	http.NotFound(w, r)
	return true
}
func sanitizeImage(raw []byte) ([]byte, string, error) {
	config, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || (format != "jpeg" && format != "png") {
		return nil, "", errors.New("Use a JPEG or PNG image")
	}
	if config.Width < 1 || config.Height < 1 || int64(config.Width)*int64(config.Height) > 12000000 {
		return nil, "", errors.New("Image must be at most 12 megapixels")
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, "", errors.New("Invalid image")
	}
	var out bytes.Buffer
	mime := "image/png"
	if format == "jpeg" {
		mime = "image/jpeg"
		err = jpeg.Encode(&out, img, &jpeg.Options{Quality: 85})
	} else {
		err = png.Encode(&out, img)
	}
	if err != nil {
		return nil, "", err
	}
	if out.Len() > 5*1024*1024 {
		return nil, "", errors.New("Processed image exceeds 5 MiB")
	}
	return out.Bytes(), mime, nil
}
