// Copyright 2022 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package database

import (
	"context"
	"database/sql"

	"github.com/juju/errors"

	"github.com/juju/juju/core/database"
)

// DBMigration is used to apply a series of deltas to a database.
type DBMigration struct {
	db     *sql.DB
	logger Logger
	deltas []database.Delta
}

// NewDBMigration returns a reference to a new migration that
// is used to apply the input deltas to the input database.
// The deltas are applied in the order supplied.
func NewDBMigration(db *sql.DB, logger Logger, deltas []database.Delta) *DBMigration {
	return &DBMigration{
		db:     db,
		logger: logger,
		deltas: deltas,
	}
}

// Apply executes all deltas against the database inside a transaction.
func (m *DBMigration) Apply(ctx context.Context) error {
	return StdTxn(ctx, m.db, func(ctx context.Context, tx *sql.Tx) error {
		for _, d := range m.deltas {
			_, err := tx.ExecContext(ctx, d.Stmt(), d.Args()...)
			if err != nil {
				return errors.Trace(err)
			}
		}
		return nil
	})
}
