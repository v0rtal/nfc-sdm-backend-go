package main

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/v0rtal/nfc-sdm-backend-go/inventory"
)

// Each integration test owns a separate schema. A mistaken connection string must
// never make fixture cleanup delete an application's real tag records.
func isolatedInventory(t *testing.T, connection string) (*inventory.Store, error) {
	t.Helper()
	ctx := context.Background()
	base, err := pgxpool.New(ctx, connection)
	if err != nil {
		return nil, err
	}
	schemaName := fmt.Sprintf("http_test_%d", time.Now().UnixNano())
	if _, err = base.Exec(ctx, "CREATE SCHEMA "+schemaName); err != nil {
		base.Close()
		return nil, err
	}
	t.Cleanup(func() { defer base.Close(); base.Exec(ctx, "DROP SCHEMA "+schemaName+" CASCADE") })
	parsed, err := url.Parse(connection)
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	query.Set("search_path", schemaName)
	parsed.RawQuery = query.Encode()
	return inventory.Open(ctx, parsed.String())
}
