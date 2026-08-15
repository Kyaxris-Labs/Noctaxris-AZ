package store

import (
	"database/sql"
	"time"
)

// UpsertEventGridTopic creates an Event Grid topic.
func (s *Store) UpsertEventGridTopic(sub, rg, name, location string) error {
	if location == "" {
		location = "eastus"
	}
	_, err := s.db.Exec(`
INSERT INTO eventgrid_topics (subscription_id, resource_group, name, location)
VALUES (?, ?, ?, ?)
ON CONFLICT(subscription_id, resource_group, name) DO UPDATE SET location=excluded.location`,
		sub, rg, name, location)
	return err
}

// GetEventGridTopicByName loads a topic by name.
func (s *Store) GetEventGridTopicByName(name string) (sub, rg, location string, ok bool, err error) {
	err = s.db.QueryRow(`
SELECT subscription_id, resource_group, location FROM eventgrid_topics WHERE name = ? LIMIT 1`, name).
		Scan(&sub, &rg, &location)
	if err == sql.ErrNoRows {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, err
	}
	return sub, rg, location, true, nil
}

// UpsertEventGridSubscription creates a subscription.
func (s *Store) UpsertEventGridSubscription(topic, name, destURL, filterJSON string) error {
	if filterJSON == "" {
		filterJSON = "{}"
	}
	_, err := s.db.Exec(`
INSERT INTO eventgrid_subscriptions (topic, name, destination_url, filter_json)
VALUES (?, ?, ?, ?)
ON CONFLICT(topic, name) DO UPDATE SET destination_url=excluded.destination_url, filter_json=excluded.filter_json`,
		topic, name, destURL, filterJSON)
	return err
}

// ListEventGridSubscriptions lists subscriptions for a topic.
func (s *Store) ListEventGridSubscriptions(topic string) ([]struct {
	Name, DestinationURL, FilterJSON string
}, error) {
	rows, err := s.db.Query(`
SELECT name, destination_url, filter_json FROM eventgrid_subscriptions WHERE topic = ?`, topic)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct {
		Name, DestinationURL, FilterJSON string
	}
	for rows.Next() {
		var row struct {
			Name, DestinationURL, FilterJSON string
		}
		if err := rows.Scan(&row.Name, &row.DestinationURL, &row.FilterJSON); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// InsertEventGridEvent stores a published event.
func (s *Store) InsertEventGridEvent(topic, bodyJSON string, delivered bool) error {
	d := 0
	if delivered {
		d = 1
	}
	_, err := s.db.Exec(`
INSERT INTO eventgrid_events (topic, body_json, delivered, inserted_at)
VALUES (?, ?, ?, ?)`, topic, bodyJSON, d, time.Now().UTC().Format(time.RFC3339))
	return err
}
