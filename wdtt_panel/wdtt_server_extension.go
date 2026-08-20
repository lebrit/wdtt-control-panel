package main

import (
	"errors"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

const wdttPanelExtensionMarker = "wdtt-panel-extension-v8"

func normalizeUserLabel(value string) (string, error) {
	label := strings.TrimSpace(value)
	if label == "-" {
		return "", nil
	}
	if len([]rune(label)) > 64 {
		return "", errors.New("label is too long")
	}
	for _, char := range label {
		if char < 32 || char == 127 {
			return "", errors.New("label contains a control character")
		}
	}
	return label, nil
}

func telegramLabel(value string) string {
	return strings.NewReplacer("\\", "\\\\", "_", "\\_", "*", "\\*", "`", "\\`", "[", "\\[").Replace(value)
}

func trafficQuota(entry *PasswordEntry) (used, primary, extra, remaining int64, exhausted bool) {
	if entry == nil || !entry.TrafficManaged || entry.TrafficUnlimited {
		return 0, 0, 0, 0, false
	}
	used = entry.DownBytes + entry.UpBytes - entry.TrafficBaselineBytes
	if used < 0 {
		used = 0
	}
	primary = entry.TrafficPrimaryBytes - used
	if primary < 0 {
		primary = 0
	}
	extraUsed := used - entry.TrafficPrimaryBytes
	if extraUsed < 0 {
		extraUsed = 0
	}
	extra = entry.TrafficExtraBytes - extraUsed
	if extra < 0 {
		extra = 0
	}
	remaining = primary + extra
	return used, primary, extra, remaining, remaining <= 0
}

func trafficQuotaExhausted(entry *PasswordEntry) bool {
	_, _, _, _, exhausted := trafficQuota(entry)
	return exhausted
}

func passwordAccessRestricted(entry *PasswordEntry) bool {
	return entry == nil || isPasswordExpired(entry) || entry.IsDeactivated || trafficQuotaExhausted(entry)
}

func passwordForEntryLocked(target *PasswordEntry) string {
	for password, entry := range db.Passwords {
		if entry == target {
			return password
		}
	}
	return ""
}

func restrictPasswordEntryLocked(password string, entry *PasswordEntry, wgDev *device.Device) {
	if password != "" {
		disconnectCredentialConnections(password)
		serverWrapKeys.RemovePassword(password)
	}
	for _, deviceID := range entryDeviceIDs(entry) {
		removePeerFromWG(wgDev, db.Devices[deviceID])
	}
}

func applyPasswordRestrictionsLocked(wgDev *device.Device) int {
	restricted := 0
	for password, entry := range db.Passwords {
		if passwordAccessRestricted(entry) {
			restrictPasswordEntryLocked(password, entry, wgDev)
			restricted++
		}
	}
	return restricted
}

func deviceAccessAllowedLocked(deviceID string, dev *ClientDevice) bool {
	entry := generatedOwnerEntryLocked(dev, deviceID)
	return entry == nil || !passwordAccessRestricted(entry)
}

func deviceUsesMainPasswordLocked(dev *ClientDevice) bool {
	if dev == nil || db.MainPassword == "" {
		return false
	}
	ownerID := wrapKeyID(db.MainPassword)
	return dev.OwnerID == ownerID || dev.RawOwnerID == ownerID
}

func recordPasswordTrafficLocked(entry *PasswordEntry, up, down int64) {
	entry.UpBytes += up
	entry.DownBytes += down
	now := time.Now().Unix()
	if up > 0 {
		entry.LastUploadAt = now
	}
	if down > 0 {
		entry.LastDownloadAt = now
	}
	if trafficQuotaExhausted(entry) {
		restrictPasswordEntryLocked(passwordForEntryLocked(entry), entry, globalWgDev)
	}
}

func recordMainTrafficLocked(up, down int64) {
	db.MainUpBytes += up
	db.MainDownBytes += down
	now := time.Now().Unix()
	if up > 0 {
		db.MainLastUploadAt = now
	}
	if down > 0 {
		db.MainLastDownloadAt = now
	}
}
