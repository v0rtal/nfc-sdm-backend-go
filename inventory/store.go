package inventory

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/v0rtal/nfc-sdm-backend-go/sdm"
)

//go:embed schema.sql
var schema string

type Store struct{ DB *pgxpool.Pool }
type Image struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}
type Tag struct {
	UID              string          `json:"uid"`
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	Attributes       json.RawMessage `json:"attributes"`
	FirstSeen        time.Time       `json:"first_seen"`
	LastSeen         time.Time       `json:"last_seen"`
	MaxCounter       *uint32         `json:"max_read_counter"`
	ScanCount        int64           `json:"scan_count"`
	RequestCount     int64           `json:"request_count"`
	TamperStatus     string          `json:"tt_status"`
	TamperDetectedAt *time.Time      `json:"tamper_detected_at,omitempty"`
	Mode             string          `json:"enc_mode"`
	Images           []Image         `json:"images"`
}
type Validity struct {
	Valid         bool       `json:"valid"`
	Status        string     `json:"status"`
	Warning       string     `json:"warning,omitempty"`
	ObservedAt    time.Time  `json:"observed_at"`
	FirstSeen     *time.Time `json:"first_seen,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Repeat        bool       `json:"repeat"`
	LatestCounter *uint32    `json:"latest_counter"`
}
type Event struct {
	ID           int64           `json:"id"`
	Counter      *uint32         `json:"read_counter"`
	ViewedAt     time.Time       `json:"viewed_at"`
	Status       string          `json:"status"`
	TamperStatus string          `json:"tt_status"`
	ClientIP     string          `json:"client_ip"`
	Location     json.RawMessage `json:"location"`
}

func Open(ctx context.Context, url string) (*Store, error) {
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	config.ConnConfig.RuntimeParams["timezone"] = "UTC"
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(ctx); err != nil {
		db.Close()
		return nil, err
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		db.Close()
		return nil, err
	}
	defer tx.Rollback(ctx)
	// Coordinate schema initialization when multiple backend processes start together.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(424424)"); err == nil {
		_, err = tx.Exec(ctx, schema)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{DB: db}, nil
}

func Decide(counter, latest *uint32, repeat bool, now time.Time, first, expires *time.Time) Validity {
	v := Validity{ObservedAt: now, FirstSeen: first, ExpiresAt: expires, Repeat: repeat, LatestCounter: latest}
	switch {
	case counter == nil:
		v.Status = "counter_missing"
		v.Warning = "Signature verified, but this tag has no read counter; link freshness cannot be checked."
	case latest != nil && *counter < *latest:
		v.Status = "stale"
		v.Warning = "This link has an older read counter. A newer tag link has already been opened. Scan the physical tag again."
	case expires != nil && !now.Before(*expires):
		v.Status = "expired"
		v.Warning = "This link's 30-second validity window has expired. Scan the physical tag again."
	case repeat:
		v.Status = "replayed"
		v.Warning = "This link has already been opened. Repeated links are not valid, even within 30 seconds. Scan the physical tag again."
	default:
		v.Status = "fresh"
		v.Valid = true
	}
	return v
}

// Observe is called only after cryptographic verification. A per-tag row lock makes
// counter comparison and first-open registration atomic across all backend processes.
func (s *Store) Observe(ctx context.Context, result sdm.Result) (Validity, error) {
	return s.ObserveTraffic(ctx, result, "", json.RawMessage(`{}`))
}
func (s *Store) ObserveTraffic(ctx context.Context, result sdm.Result, clientIP string, location json.RawMessage) (Validity, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Validity{}, err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO tags(uid,first_seen,last_seen) VALUES($1,clock_timestamp(),clock_timestamp()) ON CONFLICT DO NOTHING`, result.UID)
	if err != nil {
		return Validity{}, err
	}
	var latest *uint32
	if err = tx.QueryRow(ctx, `SELECT max_counter FROM tags WHERE uid=$1 FOR UPDATE`, result.UID).Scan(&latest); err != nil {
		return Validity{}, err
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return Validity{}, err
	}
	var first, expires *time.Time
	repeat := false
	newCount := 0
	if result.ReadCounter != nil {
		var f, e time.Time
		err = tx.QueryRow(ctx, `SELECT first_seen,expires_at FROM scans WHERE uid=$1 AND counter=$2`, result.UID, *result.ReadCounter).Scan(&f, &e)
		if errors.Is(err, pgx.ErrNoRows) {
			f = now
			e = now.Add(30 * time.Second)
			newCount = 1
			_, err = tx.Exec(ctx, `INSERT INTO scans(uid,counter,first_seen,expires_at) VALUES($1,$2,$3,$4)`, result.UID, *result.ReadCounter, f, e)
		} else if err == nil {
			repeat = true
			_, err = tx.Exec(ctx, `UPDATE scans SET opens=opens+1 WHERE uid=$1 AND counter=$2`, result.UID, *result.ReadCounter)
		}
		if err != nil {
			return Validity{}, err
		}
		first = &f
		expires = &e
	}
	validity := Decide(result.ReadCounter, latest, repeat, now, first, expires)
	if result.ReadCounter != nil && (latest == nil || *result.ReadCounter > *latest) {
		latest = result.ReadCounter
	}
	validity.LatestCounter = latest
	_, err = tx.Exec(ctx, `UPDATE tags SET last_seen=$2,max_counter=$3,scan_count=scan_count+$4,request_count=request_count+1,
 tamper_status=CASE WHEN $5 THEN $6 ELSE tamper_status END,enc_mode=CASE WHEN $5 THEN $7 ELSE enc_mode END,
 tamper_detected_at=CASE WHEN $6 IN ('tampered_closed','tampered_open') THEN COALESCE(tamper_detected_at,$2) ELSE tamper_detected_at END WHERE uid=$1`, result.UID, now, latest, newCount, validity.Valid || result.ReadCounter == nil, result.TamperStatus, result.Mode)
	if err != nil {
		return Validity{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO scan_events(uid,counter,viewed_at,status,tamper_status,client_ip,location) VALUES($1,$2,$3,$4,$5,$6,$7)`, result.UID, result.ReadCounter, now, validity.Status, result.TamperStatus, clientIP, location)
	if err != nil {
		return Validity{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Validity{}, err
	}
	return validity, nil
}

const columns = `uid,name,description,attributes,first_seen,last_seen,max_counter,scan_count,request_count,tamper_status,enc_mode,tamper_detected_at`

func readTag(row pgx.Row) (Tag, error) {
	var t Tag
	err := row.Scan(&t.UID, &t.Name, &t.Description, &t.Attributes, &t.FirstSeen, &t.LastSeen, &t.MaxCounter, &t.ScanCount, &t.RequestCount, &t.TamperStatus, &t.Mode, &t.TamperDetectedAt)
	t.Images = []Image{}
	return t, err
}
func (s *Store) Get(ctx context.Context, uid string) (Tag, error) {
	t, err := readTag(s.DB.QueryRow(ctx, "SELECT "+columns+" FROM tags WHERE uid=$1", uid))
	if err != nil {
		return t, err
	}
	rows, err := s.DB.Query(ctx, `SELECT id FROM item_images WHERE uid=$1 ORDER BY created_at,id`, uid)
	if err != nil {
		return t, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return t, err
		}
		t.Images = append(t.Images, Image{ID: id, URL: "/images/" + id})
	}
	return t, rows.Err()
}
func (s *Store) List(ctx context.Context, limit, offset int) ([]Tag, error) {
	rows, err := s.DB.Query(ctx, "SELECT "+columns+" FROM tags ORDER BY last_seen DESC,uid LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tags := []Tag{}
	for rows.Next() {
		t, e := readTag(rows)
		if e != nil {
			return nil, e
		}
		tags = append(tags, t)
	}
	return tags, rows.Err()
}
func (s *Store) Update(ctx context.Context, uid, name, description string, attributes json.RawMessage) error {
	result, err := s.DB.Exec(ctx, `UPDATE tags SET name=$2,description=$3,attributes=$4 WHERE uid=$1`, uid, name, description, attributes)
	if err == nil && result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return err
}
func (s *Store) History(ctx context.Context, uid string) ([]Event, error) {
	rows, err := s.DB.Query(ctx, `SELECT id,counter,viewed_at,status,tamper_status,client_ip,location FROM scan_events WHERE uid=$1 ORDER BY id DESC LIMIT 10`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []Event{}
	for rows.Next() {
		var e Event
		if err = rows.Scan(&e.ID, &e.Counter, &e.ViewedAt, &e.Status, &e.TamperStatus, &e.ClientIP, &e.Location); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
func (s *Store) SaveImage(ctx context.Context, id, uid, mime string, data []byte) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var exists string
	if err = tx.QueryRow(ctx, `SELECT uid FROM tags WHERE uid=$1 FOR UPDATE`, uid).Scan(&exists); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM item_images WHERE uid=$1`, uid).Scan(&count); err != nil {
		return err
	}
	if count >= 10 {
		return fmt.Errorf("image limit reached")
	}
	if _, err = tx.Exec(ctx, `INSERT INTO item_images(id,uid,mime,data) VALUES($1,$2,$3,$4)`, id, uid, mime, data); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
