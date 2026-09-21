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

// GetEventHubsNamespaceByName loads ARM coordinates for a namespace name.
func (s *Store) GetEventHubsNamespaceByName(name string) (sub, rg, location string, ok bool, err error) {
	err = s.db.QueryRow(`
SELECT subscription_id, resource_group, location FROM eventhubs_namespaces WHERE name = ? LIMIT 1`, name).
		Scan(&sub, &rg, &location)
	if err == sql.ErrNoRows {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, err
	}
	return sub, rg, location, true, nil
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

// EnqueueEventHub appends an Event Hubs message and a capture copy.
func (s *Store) EnqueueEventHub(namespace, hub, partition string, body []byte) error {
	if partition == "" {
		partition = "0"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`
INSERT INTO eventhubs_messages (namespace, hub, partition_id, body, inserted_at)
VALUES (?, ?, ?, ?, ?)`, namespace, hub, partition, body, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`
INSERT INTO eventhubs_captured (namespace, hub, partition_id, body, inserted_at)
VALUES (?, ?, ?, ?, ?)`, namespace, hub, partition, body, now); err != nil {
		return err
	}
	return tx.Commit()
}

// EventHubCapturedEvent is a captured Event Hubs payload.
type EventHubCapturedEvent struct {
	ID          int64
	PartitionID string
	Body        []byte
	InsertedAt  string
}

// ListEventHubCaptured lists captured events without dequeuing live messages.
func (s *Store) ListEventHubCaptured(namespace, hub string) ([]EventHubCapturedEvent, error) {
	rows, err := s.db.Query(`
SELECT id, partition_id, body, inserted_at FROM eventhubs_captured
WHERE namespace = ? AND hub = ? ORDER BY id ASC`, namespace, hub)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventHubCapturedEvent
	for rows.Next() {
		var ev EventHubCapturedEvent
		if err := rows.Scan(&ev.ID, &ev.PartitionID, &ev.Body, &ev.InsertedAt); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	if out == nil {
		out = []EventHubCapturedEvent{}
	}
	return out, rows.Err()
}

// GetEventHubCaptured loads one captured event.
func (s *Store) GetEventHubCaptured(namespace, hub string, id int64) (EventHubCapturedEvent, bool, error) {
	var ev EventHubCapturedEvent
	err := s.db.QueryRow(`
SELECT id, partition_id, body, inserted_at FROM eventhubs_captured
WHERE namespace = ? AND hub = ? AND id = ?`, namespace, hub, id).
		Scan(&ev.ID, &ev.PartitionID, &ev.Body, &ev.InsertedAt)
	if err == sql.ErrNoRows {
		return EventHubCapturedEvent{}, false, nil
	}
	if err != nil {
		return EventHubCapturedEvent{}, false, err
	}
	return ev, true, nil
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
