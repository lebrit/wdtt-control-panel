package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPanelDatabaseRoundTripPreservesQuotaAndActivity(t *testing.T) {
	want := &Database{
		MainPassword:       "owner-password",
		AdminID:            "12345",
		BotToken:           "token",
		MainDownBytes:      101,
		MainUpBytes:        202,
		MainLastUploadAt:   303,
		MainLastDownloadAt: 404,
		Passwords: map[string]*PasswordEntry{
			"user-password": {
				Label:                "Пользователь",
				LastUploadAt:         11,
				LastDownloadAt:       12,
				TrafficManaged:       true,
				TrafficBaselineBytes: 13,
				TrafficPrimaryBytes:  14,
				TrafficExtraBytes:    15,
				TrafficOperations: []map[string]interface{}{
					{"id": "operation-1", "bytes": float64(16)},
				},
			},
		},
		Devices: map[string]*ClientDevice{},
	}

	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got Database
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	entry := got.Passwords["user-password"]
	if got.MainPassword != want.MainPassword || got.MainDownBytes != 101 || got.MainLastDownloadAt != 404 {
		t.Fatalf("main fields were not preserved: %#v", got)
	}
	if entry == nil || entry.Label != "Пользователь" || entry.TrafficPrimaryBytes != 14 || len(entry.TrafficOperations) != 1 {
		t.Fatalf("user fields were not preserved: %#v", entry)
	}
}

func TestPanelQuotaSpendsPrimaryBeforeExtra(t *testing.T) {
	entry := &PasswordEntry{
		DownBytes:           120,
		TrafficManaged:      true,
		TrafficPrimaryBytes: 100,
		TrafficExtraBytes:   50,
	}
	used, primary, extra, remaining, exhausted := trafficQuota(entry)
	if used != 120 || primary != 0 || extra != 30 || remaining != 30 || exhausted {
		t.Fatalf("unexpected quota: used=%d primary=%d extra=%d remaining=%d exhausted=%v", used, primary, extra, remaining, exhausted)
	}
}

func TestPanelExpiredUsersAreRetained(t *testing.T) {
	previous := db
	defer func() { db = previous }()
	db = &Database{
		MainPassword: "owner-password",
		Passwords: map[string]*PasswordEntry{
			"expired-user": {ExpiresAt: time.Now().Add(-time.Hour).Unix()},
		},
		Devices: map[string]*ClientDevice{},
	}
	if restricted := cleanupExpiredPasswordsLocked(nil); restricted != 1 {
		t.Fatalf("expected one restricted user, got %d", restricted)
	}
	if _, exists := db.Passwords["expired-user"]; !exists {
		t.Fatal("expired user was deleted")
	}
}
