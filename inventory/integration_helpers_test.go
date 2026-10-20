package inventory

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

func openTestPool(ctx context.Context, config *pgxpool.Config) (*Store, error) {
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	if _, err = pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{DB: pool}, nil
}
