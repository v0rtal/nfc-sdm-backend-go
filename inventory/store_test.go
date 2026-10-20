package inventory

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/v0rtal/nfc-sdm-backend-go/sdm"
)

func TestValidity(t *testing.T) {
	now := time.Now()
	first := now
	expiry := now.Add(30 * time.Second)
	n := uint32(20)
	older := uint32(19)
	for _, test := range []struct {
		name    string
		counter *uint32
		repeat  bool
		at      time.Time
		want    string
	}{
		{"first", &n, false, now, "fresh"}, {"immediate repeat", &n, true, now, "replayed"},
		{"expired at boundary", &n, true, expiry, "expired"}, {"older unseen", &older, false, now, "stale"}, {"missing", nil, false, now, "counter_missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := Decide(test.counter, &n, test.repeat, test.at, &first, &expiry)
			if got.Status != test.want || got.Valid != (test.want == "fresh") {
				t.Fatalf("%+v", got)
			}
		})
	}
}

// Uses its own schema and drops only that schema. Never touches application tables.
func TestPostgresConcurrencyAndPersistence(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL for real PostgreSQL tests")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	base := &Store{DB: pool}
	defer base.DB.Close()
	schemaName := fmt.Sprintf("test_inventory_%d", time.Now().UnixNano())
	if _, err = base.DB.Exec(ctx, "CREATE SCHEMA "+schemaName); err != nil {
		t.Fatal(err)
	}
	defer base.DB.Exec(ctx, "DROP SCHEMA "+schemaName+" CASCADE")
	config := base.DB.Config().Copy()
	config.ConnConfig.RuntimeParams["search_path"] = schemaName
	db, err := openTestPool(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer db.DB.Close()
	n := uint32(50)
	result := sdm.Result{UID: "04112233445566", ReadCounter: &n, Mode: "AES", TamperStatus: "secure"}
	var wg sync.WaitGroup
	out := make(chan Validity, 12)
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := db.Observe(ctx, result)
			if e != nil {
				errs <- e
			} else {
				out <- v
			}
		}()
	}
	wg.Wait()
	close(out)
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	fresh := 0
	for v := range out {
		if v.Valid {
			fresh++
		} else if v.Status != "replayed" {
			t.Fatalf("%+v", v)
		}
	}
	if fresh != 1 {
		t.Fatalf("fresh=%d", fresh)
	}
	tag, err := db.Get(ctx, result.UID)
	if err != nil {
		t.Fatal(err)
	}
	if tag.ScanCount != 1 || tag.RequestCount != 12 || *tag.MaxCounter != 50 {
		t.Fatalf("%+v", tag)
	}
	if err = db.Update(ctx, result.UID, "Test item", "Description", []byte(`{"serial":"A123"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.DB.Exec(ctx, `UPDATE scans SET expires_at=clock_timestamp()-interval '1 second' WHERE uid=$1`, result.UID); err != nil {
		t.Fatal(err)
	}
	v, err := db.Observe(ctx, result)
	if err != nil || v.Status != "expired" {
		t.Fatalf("%+v %v", v, err)
	}
	n = 49
	v, err = db.Observe(ctx, result)
	if err != nil || v.Status != "stale" {
		t.Fatalf("%+v %v", v, err)
	}
	n = 51
	v, err = db.Observe(ctx, result)
	if err != nil || !v.Valid {
		t.Fatalf("%+v %v", v, err)
	}
	tag, err = db.Get(ctx, result.UID)
	if err != nil || tag.Name != "Test item" || *tag.MaxCounter != 51 {
		t.Fatalf("%+v %v", tag, err)
	}
	events, err := db.History(ctx, result.UID)
	if err != nil || len(events) != 10 {
		t.Fatalf("events=%d %v", len(events), err)
	}
	if tag.TamperDetectedAt != nil {
		t.Fatal("Secure reads recorded tampering")
	}
	n = 52
	result.TamperStatus = "tampered_open"
	v, err = db.Observe(ctx, result)
	if err != nil {
		t.Fatal(err)
	}
	firstDetected := v.ObservedAt
	tag, err = db.Get(ctx, result.UID)
	if err != nil || tag.TamperDetectedAt == nil || !tag.TamperDetectedAt.Equal(firstDetected) {
		t.Fatalf("%+v %v", tag, err)
	}
	result.TamperStatus = "tampered_closed"
	if _, err = db.Observe(ctx, result); err != nil {
		t.Fatal(err)
	}
	n = 53
	result.TamperStatus = "secure"
	if _, err = db.Observe(ctx, result); err != nil {
		t.Fatal(err)
	}
	tag, err = db.Get(ctx, result.UID)
	if err != nil || tag.TamperDetectedAt == nil || !tag.TamperDetectedAt.Equal(firstDetected) {
		t.Fatal("First detection timestamp changed", err)
	}
	if _, err = db.DB.Exec(ctx, `UPDATE tags SET tamper_detected_at=NULL; DELETE FROM inventory_schema WHERE version=3`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.DB.Exec(ctx, schema); err != nil {
		t.Fatal(err)
	}
	tag, err = db.Get(ctx, result.UID)
	if err != nil || tag.TamperDetectedAt == nil || !tag.TamperDetectedAt.Equal(firstDetected) {
		t.Fatal("Tamper history backfill failed", err)
	}
}
