package store

import (
	"database/sql"
	"time"
)

// EnqueueSBWithMeta appends a Service Bus message with session / dead-letter flags.
func (s *Store) EnqueueSBWithMeta(namespace, queue string, body []byte, sessionID string, deadLetter bool) error {
	dl := 0
	if deadLetter {
		dl = 1
	}
	_, err := s.db.Exec(`
INSERT INTO servicebus_messages (namespace, queue, body, locked_until, inserted_at, session_id, dead_letter)
VALUES (?, ?, ?, '', ?, ?, ?)`, namespace, queue, body, time.Now().UTC().Format(time.RFC3339), sessionID, dl)
	return err
}

// DequeueSBWithMeta dequeues matching session / dead-letter filters.
func (s *Store) DequeueSBWithMeta(namespace, queue, sessionID string, deadLetter bool) (body []byte, ok bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()
	dl := 0
	if deadLetter {
		dl = 1
	}
	var id int64
	if sessionID != "" {
		err = tx.QueryRow(`
SELECT id, body FROM servicebus_messages
WHERE namespace = ? AND queue = ? AND dead_letter = ? AND session_id = ?
ORDER BY id ASC LIMIT 1`, namespace, queue, dl, sessionID).Scan(&id, &body)
	} else {
		err = tx.QueryRow(`
SELECT id, body FROM servicebus_messages
WHERE namespace = ? AND queue = ? AND dead_letter = ?
ORDER BY id ASC LIMIT 1`, namespace, queue, dl).Scan(&id, &body)
	}
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if _, err := tx.Exec(`DELETE FROM servicebus_messages WHERE id = ?`, id); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return body, true, nil
}

// CreateServiceBusTopic creates a topic.
func (s *Store) CreateServiceBusTopic(namespace, name string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO servicebus_topics (namespace, name) VALUES (?, ?)`, namespace, name)
	return err
}

// CreateServiceBusSubscription creates a subscription under a topic.
func (s *Store) CreateServiceBusSubscription(namespace, topic, name, filterSQL string) error {
	_, err := s.db.Exec(`
INSERT OR IGNORE INTO servicebus_subscriptions (namespace, topic, name, filter_sql)
VALUES (?, ?, ?, ?)`, namespace, topic, name, filterSQL)
	return err
}

// ListServiceBusSubscriptions lists subscriptions for a topic.
func (s *Store) ListServiceBusSubscriptions(namespace, topic string) ([]string, error) {
	rows, err := s.db.Query(`
SELECT name FROM servicebus_subscriptions WHERE namespace = ? AND topic = ? ORDER BY name`, namespace, topic)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// EnqueueSBTopic fans out a message to all subscriptions (or one).
func (s *Store) EnqueueSBTopic(namespace, topic, subscription string, body []byte) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if subscription != "" {
		_, err := s.db.Exec(`
INSERT INTO servicebus_topic_messages (namespace, topic, subscription, body, inserted_at)
VALUES (?, ?, ?, ?, ?)`, namespace, topic, subscription, body, now)
		return err
	}
	subs, err := s.ListServiceBusSubscriptions(namespace, topic)
	if err != nil {
		return err
	}
	for _, sub := range subs {
		if _, err := s.db.Exec(`
INSERT INTO servicebus_topic_messages (namespace, topic, subscription, body, inserted_at)
VALUES (?, ?, ?, ?, ?)`, namespace, topic, sub, body, now); err != nil {
			return err
		}
	}
	return nil
}

// DequeueSBTopic dequeues from a topic subscription.
func (s *Store) DequeueSBTopic(namespace, topic, subscription string) ([]byte, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var id int64
	var body []byte
	err = tx.QueryRow(`
SELECT id, body FROM servicebus_topic_messages
WHERE namespace = ? AND topic = ? AND subscription = ?
ORDER BY id ASC LIMIT 1`, namespace, topic, subscription).Scan(&id, &body)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if _, err := tx.Exec(`DELETE FROM servicebus_topic_messages WHERE id = ?`, id); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return body, true, nil
}
