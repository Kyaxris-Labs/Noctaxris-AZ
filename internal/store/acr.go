package store

import (
	"database/sql"

	"github.com/google/uuid"
)

// CreateACRUpload starts a Registry V2 blob upload session.
func (s *Store) CreateACRUpload(name string) (id string, err error) {
	id = uuid.NewString()
	_, err = s.db.Exec(`INSERT INTO acr_uploads (uuid, name, content) VALUES (?, ?, X'')`, id, name)
	if err != nil {
		return "", err
	}
	return id, nil
}

// ACRUploadExists reports whether an upload uuid is still open.
func (s *Store) ACRUploadExists(id string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM acr_uploads WHERE uuid = ?`, id).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// FinishACRUpload stores a blob by digest and drops the upload session.
func (s *Store) FinishACRUpload(id, digest string, content []byte, contentType string) error {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var name string
	err = tx.QueryRow(`SELECT name FROM acr_uploads WHERE uuid = ?`, id).Scan(&name)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`
INSERT INTO acr_blobs (digest, content, content_type) VALUES (?, ?, ?)
ON CONFLICT(digest) DO UPDATE SET content=excluded.content, content_type=excluded.content_type`,
		digest, content, contentType); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM acr_uploads WHERE uuid = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// PutACRBlob stores a blob by digest.
func (s *Store) PutACRBlob(digest string, content []byte, contentType string) error {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	_, err := s.db.Exec(`
INSERT INTO acr_blobs (digest, content, content_type) VALUES (?, ?, ?)
ON CONFLICT(digest) DO UPDATE SET content=excluded.content, content_type=excluded.content_type`,
		digest, content, contentType)
	return err
}

// GetACRBlob loads a blob by digest.
func (s *Store) GetACRBlob(digest string) (content []byte, contentType string, ok bool, err error) {
	err = s.db.QueryRow(`SELECT content, content_type FROM acr_blobs WHERE digest = ?`, digest).
		Scan(&content, &contentType)
	if err == sql.ErrNoRows {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	return content, contentType, true, nil
}

// PutACRManifest stores a manifest under a tag or digest reference.
func (s *Store) PutACRManifest(name, reference, digest string, content []byte, mediaType string) error {
	if mediaType == "" {
		mediaType = "application/vnd.docker.distribution.manifest.v2+json"
	}
	_, err := s.db.Exec(`
INSERT INTO acr_manifests (name, reference, digest, content, media_type)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(name, reference) DO UPDATE SET digest=excluded.digest, content=excluded.content, media_type=excluded.media_type`,
		name, reference, digest, content, mediaType)
	return err
}

// GetACRManifest loads a manifest by repository name and tag or digest.
func (s *Store) GetACRManifest(name, reference string) (content []byte, digest, mediaType string, ok bool, err error) {
	err = s.db.QueryRow(`
SELECT content, digest, media_type FROM acr_manifests WHERE name = ? AND reference = ?`, name, reference).
		Scan(&content, &digest, &mediaType)
	if err == sql.ErrNoRows {
		return nil, "", "", false, nil
	}
	if err != nil {
		return nil, "", "", false, err
	}
	return content, digest, mediaType, true, nil
}
