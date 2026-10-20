package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/v0rtal/nfc-sdm-backend-go/inventory"
	"github.com/v0rtal/nfc-sdm-backend-go/sdm"
)

func env(k, d string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return d
}
func configuration() (sdm.Verifier, error) {
	// Missing configuration must never silently enable factory keys on a public server.
	masterHex := env("MASTER_KEY", "")
	if masterHex == "" {
		return sdm.Verifier{}, errors.New("MASTER_KEY is required; generate one with keygen")
	}
	master, err := hex.DecodeString(masterHex)
	if err != nil || (len(master) != 16 && len(master) != 32) {
		return sdm.Verifier{}, errors.New("MASTER_KEY must be 16 or 32 hex-encoded bytes")
	}
	if masterHex == strings.Repeat("0", 32) && env("ALLOW_FACTORY_KEYS", "0") != "1" {
		return sdm.Verifier{}, errors.New("factory keys require explicit ALLOW_FACTORY_KEYS=1; never use them for deployed tags")
	}
	mode := env("DERIVE_MODE", "legacy")
	if mode != "legacy" && mode != "standard" {
		return sdm.Verifier{}, errors.New("DERIVE_MODE must be legacy or standard")
	}
	require := env("REQUIRE_LRP", "0")
	if require != "0" && require != "1" {
		return sdm.Verifier{}, errors.New("REQUIRE_LRP must be 0 or 1")
	}
	return sdm.Verifier{Master: master, DeriveMode: mode, MACParam: env("SDMMAC_PARAM", "cmac"), RequireLRP: require == "1"}, nil
}
func decode(q url.Values, k string, required bool) ([]byte, error) {
	values := q[k]
	if len(values) > 1 {
		return nil, fmt.Errorf("duplicate parameter %s", k)
	}
	s := q.Get(k)
	if s == "" {
		if required {
			return nil, fmt.Errorf("parameter %s is required", k)
		}
		return nil, nil
	}
	b, e := hex.DecodeString(s)
	if e != nil {
		return nil, fmt.Errorf("parameter %s must be hexadecimal", k)
	}
	return b, nil
}

//go:embed web/result.html
var resultHTML string

//go:embed web/admin.html
var adminPage string
var resultPage = template.Must(template.New("result").Parse(resultHTML))

func handler(v sdm.Verifier) http.Handler {
	return handlerWithBackend(v, &backend{})
}
func handlerWithBackend(v sdm.Verifier, b *backend) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.URL.Path == "/downloads/NFC-Tag-Writer-debug.apk" {
			if r.Method != "GET" && r.Method != "HEAD" {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", 405)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.android.package-archive")
			w.Header().Set("Content-Disposition", `attachment; filename="NFC-Tag-Writer-debug.apk"`)
			// The Android app is independent; operators may publish a built APK at this path.
			http.ServeFile(w, r, env("APK_PATH", "dist/NFC-Tag-Writer-debug.apk"))
			return
		}
		if b.routes(w, r) {
			return
		}
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", 405)
			return
		}
		if r.URL.Path == "/healthz" {
			if b.store != nil {
				ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
				defer cancel()
				if err := b.store.DB.Ping(ctx); err != nil {
					http.Error(w, "database unavailable", 503)
					return
				}
			}
			w.Write([]byte("ok\n"))
			return
		}
		if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/items/") {
			b.directory(w, r)
			return
		}
		if r.URL.Path == "/webnfc" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, webNFC)
			return
		}
		plain := r.URL.Path == "/tagpt" || r.URL.Path == "/api/tagpt"
		tt := r.URL.Path == "/tagtt" || r.URL.Path == "/api/tagtt"
		if !plain && !tt && r.URL.Path != "/tag" && r.URL.Path != "/api/tag" {
			http.NotFound(w, r)
			return
		}
		if len(r.URL.RawQuery) > 4096 {
			http.Error(w, "query too long", 414)
			return
		}
		q, err := url.ParseQuery(r.URL.RawQuery)
		var result sdm.Result
		if err == nil {
			result, err = verifyQuery(v, q, plain, tt)
		}
		signatureValid := err == nil
		counterfeit := errors.Is(err, sdm.ErrInvalid)
		var validity *inventory.Validity
		var item *inventory.Tag
		databaseFailed := false
		if err == nil && b.store != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
			defer cancel()
			clientIP := ""
			location := json.RawMessage(`{}`)
			if b.traffic != nil {
				clientIP, location = b.traffic.record(ctx, r)
			}
			observed, e := b.store.ObserveTraffic(ctx, result, clientIP, location)
			if e == nil {
				validity = &observed
				var tag inventory.Tag
				tag, e = b.store.Get(ctx, result.UID)
				if e == nil {
					item = &tag
				}
			}
			if e != nil {
				log.Printf("Scan tracking failed: %v", e)
				err = errors.New("Database unavailable; link freshness could not be checked. Try again later.")
				databaseFailed = true
			}
		}
		asJSON := strings.HasPrefix(r.URL.Path, "/api/") || q.Get("output") == "json"
		if asJSON {
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				if databaseFailed {
					w.WriteHeader(503)
				} else {
					w.WriteHeader(400)
				}
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			output := map[string]any{"uid": result.UID, "read_ctr": result.ReadCounter, "enc_mode": result.Mode, "signature_valid": true, "tracking_enabled": b.store != nil, "link_valid": false}
			if !plain {
				output["file_data"] = result.FileData
				output["tt_status"] = result.TamperStatus
			}
			if validity != nil {
				output["link_valid"] = validity.Valid
				output["link_validity"] = validity
				output["item"] = item
			} else {
				output["warning"] = "Database tracking is disabled; link freshness is not checked."
			}
			json.NewEncoder(w).Encode(output)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page := struct {
			Error, JSON, Attributes, ObservedISO string
			TagID                                string
			Validity                             *inventory.Validity
			Item                                 *inventory.Tag
			ShowHistory                          bool
			History                              []publicScanEvent
			Authentic, Counterfeit               bool
			TamperLabel, TamperClass             string
		}{Validity: validity, Item: item, ShowHistory: tt, Authentic: signatureValid, Counterfeit: counterfeit, ObservedISO: time.Now().UTC().Format(time.RFC3339Nano)}
		page.TamperLabel, page.TamperClass = tamperBadge(result.TamperStatus, signatureValid)
		if signatureValid {
			page.TagID = result.UID
		}
		if err == nil && tt && b.store != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			events, e := b.store.History(ctx, result.UID)
			cancel()
			if e != nil {
				log.Printf("Scan history failed: %v", e)
				err = errors.New("Scan history is temporarily unavailable. Try again later.")
				databaseFailed = true
			} else {
				for _, event := range events {
					page.History = append(page.History, publicScanEvent{ViewedAt: event.ViewedAt.UTC(), Counter: event.Counter, Status: event.Status, TamperStatus: event.TamperStatus})
				}
			}
		}
		if err != nil {
			if databaseFailed {
				w.WriteHeader(503)
			} else {
				w.WriteHeader(400)
			}
			page.Error = err.Error()
		} else {
			b, _ := json.MarshalIndent(result, "", "  ")
			page.JSON = string(b)
			if item != nil && string(item.Attributes) != "{}" {
				page.Attributes = string(item.Attributes)
			}
		}
		if err := resultPage.Execute(w, page); err != nil {
			log.Printf("Render verification page: %v", err)
		}
	})
}
func verifyQuery(v sdm.Verifier, q url.Values, plain, tt bool) (sdm.Result, error) {
	invalid := func(e error) (sdm.Result, error) { return sdm.Result{}, e }
	if plain {
		uid, e := decode(q, env("UID_PARAM", "uid"), true)
		if e != nil {
			return invalid(e)
		}
		ctr, e := decode(q, env("CTR_PARAM", "ctr"), true)
		if e != nil {
			return invalid(e)
		}
		mac, e := decode(q, v.MACParam, true)
		if e != nil {
			return invalid(e)
		}
		return v.Plain(uid, ctr, mac)
	}
	bulk := q.Get("e") != ""
	var picc, file, mac []byte
	var e error
	if bulk {
		b, err := decode(q, "e", true)
		if err != nil {
			return invalid(err)
		}
		p := 16
		if len(b) >= 32 && (len(b)-32)%16 == 0 {
			p = 24
		} else if len(b) < 24 || (len(b)-24)%16 != 0 {
			return invalid(errors.New("incorrect bulk parameter length"))
		}
		picc = b[:p]
		file = b[p : len(b)-8]
		mac = b[len(b)-8:]
	} else {
		picc, e = decode(q, env("ENC_PICC_DATA_PARAM", "picc_data"), true)
		if e != nil {
			return invalid(e)
		}
		file, e = decode(q, env("ENC_FILE_DATA_PARAM", "enc"), false)
		if e != nil {
			return invalid(e)
		}
		mac, e = decode(q, v.MACParam, true)
		if e != nil {
			return invalid(e)
		}
	}
	return v.Encrypted(picc, file, mac, bulk, tt)
}

const webNFC = `<!doctype html><html><title>Web NFC</title><h1>Read an NFC tag</h1><p>Requires HTTPS and a browser with Web NFC support. This reads NDEF; it cannot provision SDM keys.</p><button id="scan">Scan</button><pre id="out"></pre><script>document.getElementById('scan').onclick=async()=>{const out=document.getElementById('out');try{const reader=new NDEFReader();await reader.scan();reader.onreading=e=>{out.textContent='';for(const r of e.message.records){out.textContent+=new TextDecoder(r.encoding||'utf-8').decode(r.data)+'\n';}};reader.onreadingerror=()=>{out.textContent='Unable to read tag';};}catch(e){out.textContent=e.message;}};</script></html>`

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		b := make([]byte, 16)
		if _, e := rand.Read(b); e != nil {
			log.Fatal(e)
		}
		fmt.Println(hex.EncodeToString(b))
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "ndef" {
		if e := ndef(os.Args[2:]); e != nil {
			log.Fatal(e)
		}
		return
	}
	v, err := configuration()
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) > 1 && os.Args[1] == "derive" {
		if len(os.Args) != 3 {
			log.Fatal("usage: nfctag derive UID_HEX")
		}
		uid, e := hex.DecodeString(os.Args[2])
		if e != nil || len(uid) != 7 {
			log.Fatal("UID must be seven hex-encoded bytes")
		}
		keys := map[string]string{}
		for n := byte(0); n < 5; n++ {
			keys[fmt.Sprintf("key_%d", n)] = hex.EncodeToString(sdm.DeriveKey(v.Master, uid, n, v.DeriveMode, n == 1))
		}
		json.NewEncoder(os.Stdout).Encode(keys)
		return
	}
	host := flag.String("host", "0.0.0.0", "listen address")
	port := flag.Int("port", 5000, "listen port")
	flag.Parse()
	if hex.EncodeToString(v.Master) == strings.Repeat("0", 32) {
		log.Print("Factory-key demo mode; configure MASTER_KEY for provisioned tags")
	}
	addr := env("LISTEN_ADDR", fmt.Sprintf("%s:%d", *host, *port))
	b := &backend{adminToken: env("ADMIN_TOKEN", "")}
	b.traffic, err = newTrafficRecorder()
	if err != nil {
		log.Fatal(err)
	}
	if databaseURL := env("DATABASE_URL", ""); databaseURL != "" {
		if len(b.adminToken) < 8 {
			log.Fatal("ADMIN_TOKEN must contain at least 8 characters when DATABASE_URL is set; use a separate management password")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		b.store, err = inventory.Open(ctx, databaseURL)
		cancel()
		if err != nil {
			log.Fatal("PostgreSQL startup failed: ", err)
		}
		defer b.store.DB.Close()
		log.Print("PostgreSQL inventory and strict replay checking enabled (30-second first-opening window)")
	}
	serveHandler := handlerWithBackend(v, b)
	newServer := func(address string) *http.Server {
		return &http.Server{Addr: address, Handler: serveHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8192}
	}
	// Validate certificates and bind both ports before serving either endpoint.
	httpsAddr := env("HTTPS_ADDR", "")
	var httpsServer *http.Server
	var httpsListener net.Listener
	if httpsAddr != "" {
		certificate, e := tls.LoadX509KeyPair(env("TLS_CERT", ""), env("TLS_KEY", ""))
		if e != nil {
			log.Fatalf("HTTPS certificate: %v", e)
		}
		httpsServer = newServer(httpsAddr)
		httpsServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
		httpsListener, e = net.Listen("tcp", httpsAddr)
		if e != nil {
			log.Fatal(e)
		}
	}
	httpListener, err := net.Listen("tcp", addr)
	if err != nil {
		if httpsListener != nil {
			httpsListener.Close()
		}
		log.Fatal(err)
	}
	if httpsServer != nil {
		log.Printf("Listening HTTPS on %s", httpsAddr)
		go func() { log.Fatal(httpsServer.ServeTLS(httpsListener, "", "")) }()
	}
	log.Printf("Listening HTTP on %s", addr)
	log.Fatal(newServer(addr).Serve(httpListener))
}
