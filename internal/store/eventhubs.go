package store

import (
	"database/sql"
	"time"
)

// UpsertEventHubsNamespace creates an Event Hubs namespace.
func (s *Store) UpsertEventHubsNamespace(sub, rg, name, location string) error {
	if location == "" {
		location = "eastus"
	}
	_, err := s.db.Exec(`
INSERT INTO eventhubs_namespaces (subscription_id, resource_group, name, location)
VALUES (?, ?, ?, ?)
ON CONFLICT(subscription_id, resource_group, name) DO UPDATE SET location=excluded.location`,
		sub, rg, name, location)
	return err
}

// GetEventHubsNamespace loads a namespace location.
func (s *Store) GetEventHubsNamespace(sub, rg, name string) (location string, ok bool, err error) {
	err = s.db.QueryRow(`
SELECT location FROM eventhubs_namespaces
WHERE subscription_id = ? AND resource_group = ? AND name = ?`, sub, rg, name).Scan(&location)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return location, true, nil
}

// CreateEventHub creates a hub under a namespace.
func (s *Store) CreateEventHub(namespace, name string, partitions int) error {
	if partitions <= 0 {
		partitions = 2
	}
	_, err := s.db.Exec(`
INSERT INTO eventhubs_hubs (namespace, name, partition_count) VALUES (?, ?, ?)
ON CONFLICT(namespace, name) DO UPDATE SET partition_count=excluded.partition_count`,
		namespace, name, partitions)
	return err
}

// CreateEventHubConsumerGroup creates a consumer group.
func (s *Store) CreateEventHubConsumerGroup(namespace, hub, name string) error {
	_, err := s.db.Exec(`
INSERT OR IGNORE INTO eventhubs_consumer_groups (namespace, hub, name) VALUES (?, ?, ?)`,
		namespace, hub, name)
	return err
}

// EnqueueEventHub appends an Event Hubs message.
func (s *Store) EnqueueEventHub(namespace, hub, partition string, body []byte) error {
	if partition == "" {
		partition = "0"
	}
	_, err := s.db.Exec(`
INSERT INTO eventhubs_messages (namespace, hub, partition_id, body, inserted_at)
VALUES (?, ?, ?, ?, ?)`, namespace, hub, partition, body, time.Now().UTC().Format(time.RFC3339))
	return err
}

// DequeueEventHub dequeues the oldest Event Hubs message.
func (s *Store) DequeueEventHub(namespace, hub, partition string) ([]byte, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var id int64
	var body []byte
	if partition != "" {
		err = tx.QueryRow(`
SELECT id, body FROM eventhubs_messages
WHERE namespace = ? AND hub = ? AND partition_id = ?
ORDER BY id ASC LIMIT 1`, namespace, hub, partition).Scan(&id, &body)
	} else {
		err = tx.QueryRow(`
SELECT id, body FROM eventhubs_messages
WHERE namespace = ? AND hub = ?
ORDER BY id ASC LIMIT 1`, namespace, hub).Scan(&id, &body)
	}
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if _, err := tx.Exec(`DELETE FROM eventhubs_messages WHERE id = ?`, id); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return body, true, nil
}

