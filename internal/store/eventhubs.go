package store

import (
	"database/sql"
	"strings"
	"time"
)

// EventHubNamespaceKey is the durable data-plane key for hubs/messages/capture (ARM resource id).
func EventHubNamespaceKey(sub, rg, name string) string {
	return "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.EventHub/namespaces/" + name
}

// EventHubsNamespaceRow is an ARM namespace coordinate.
type EventHubsNamespaceRow struct {
	SubscriptionID string
	ResourceGroup  string
	Name           string
	Location       string
}

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

// ListEventHubsNamespacesByName lists all ARM namespaces with the given name.
func (s *Store) ListEventHubsNamespacesByName(name string) ([]EventHubsNamespaceRow, error) {
	rows, err := s.db.Query(`
SELECT subscription_id, resource_group, name, location FROM eventhubs_namespaces
WHERE name = ? ORDER BY subscription_id, resource_group`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventHubsNamespaceRow
	for rows.Next() {
		var row EventHubsNamespaceRow
		if err := rows.Scan(&row.SubscriptionID, &row.ResourceGroup, &row.Name, &row.Location); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if out == nil {
		out = []EventHubsNamespaceRow{}
	}
	return out, rows.Err()
}

// GetEventHubsNamespaceByName loads ARM coordinates for a namespace name.
// When multiple resource groups share the name, returns the first row (prefer ListEventHubsNamespacesByName).
func (s *Store) GetEventHubsNamespaceByName(name string) (sub, rg, location string, ok bool, err error) {
	list, err := s.ListEventHubsNamespacesByName(name)
	if err != nil || len(list) == 0 {
		return "", "", "", false, err
	}
	return list[0].SubscriptionID, list[0].ResourceGroup, list[0].Location, true, nil
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

// CreateEventHub creates a hub under a namespace key (prefer EventHubNamespaceKey).
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
	return s.ListEventHubCapturedForNamespaces([]string{namespace}, hub)
}

// ListEventHubCapturedForNamespaces lists captured events for any of the namespace keys.
func (s *Store) ListEventHubCapturedForNamespaces(namespaces []string, hub string) ([]EventHubCapturedEvent, error) {
	namespaces = trimNonEmpty(namespaces)
	if len(namespaces) == 0 {
		return []EventHubCapturedEvent{}, nil
	}
	args := make([]any, 0, len(namespaces)+1)
	placeholders := make([]string, 0, len(namespaces))
	for _, ns := range namespaces {
		placeholders = append(placeholders, "?")
		args = append(args, ns)
	}
	args = append(args, hub)
	q := `
SELECT id, partition_id, body, inserted_at FROM eventhubs_captured
WHERE namespace IN (` + strings.Join(placeholders, ",") + `) AND hub = ? ORDER BY id ASC`
	rows, err := s.db.Query(q, args...)
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
	return s.GetEventHubCapturedForNamespaces([]string{namespace}, hub, id)
}

// GetEventHubCapturedForNamespaces loads one captured event under any authorized namespace key.
func (s *Store) GetEventHubCapturedForNamespaces(namespaces []string, hub string, id int64) (EventHubCapturedEvent, bool, error) {
	namespaces = trimNonEmpty(namespaces)
	if len(namespaces) == 0 {
		return EventHubCapturedEvent{}, false, nil
	}
	args := make([]any, 0, len(namespaces)+2)
	placeholders := make([]string, 0, len(namespaces))
	for _, ns := range namespaces {
		placeholders = append(placeholders, "?")
		args = append(args, ns)
	}
	args = append(args, hub, id)
	var ev EventHubCapturedEvent
	err := s.db.QueryRow(`
SELECT id, partition_id, body, inserted_at FROM eventhubs_captured
WHERE namespace IN (`+strings.Join(placeholders, ",")+`) AND hub = ? AND id = ?`, args...).
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

func trimNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
