package repo

import (
	"manyrows-core/db"
)

type Repo struct {
	db *db.DB
}

func NewRepo(db *db.DB) *Repo {
	return &Repo{db: db}
}

func (r *Repo) DB() *db.DB {
	return r.db
}

func (r *Repo) Shutdown() {
	r.db.Shutdown()
}
