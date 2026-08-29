package server

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type syncConsumerHealth struct {
	mu sync.RWMutex

	rid         int
	partition   string
	providers   []string
	state       string
	provider    string
	attempts    uint64
	retries     uint64
	lastAttempt time.Time
	lastSuccess time.Time
	degradedAt  time.Time
	lastError   string
	cookie      []byte
}

type syncConsumerHealthSnapshot struct {
	rid         int
	partition   string
	providers   []string
	state       string
	provider    string
	attempts    uint64
	retries     uint64
	lastAttempt time.Time
	lastSuccess time.Time
	degradedAt  time.Time
	lastError   string
	cookie      []byte
}

func newSyncConsumerHealth(config syncConsumerConfig) *syncConsumerHealth {
	return &syncConsumerHealth{
		rid:       config.rid,
		partition: config.partition,
		providers: append([]string(nil), config.providerURLs...),
		state:     "starting",
	}
}

func (health *syncConsumerHealth) beginAttempt(provider string, now time.Time) {
	health.mu.Lock()
	health.state = "connecting"
	health.provider = provider
	health.attempts++
	health.lastAttempt = now.UTC()
	if health.degradedAt.IsZero() {
		health.degradedAt = now.UTC()
	}
	health.mu.Unlock()
}

func (health *syncConsumerHealth) connected() {
	health.mu.Lock()
	health.state = "synchronizing"
	health.mu.Unlock()
}

func (health *syncConsumerHealth) loadedCookie(cookie []byte) {
	health.mu.Lock()
	health.cookie = bytes.Clone(cookie)
	health.mu.Unlock()
}

func (health *syncConsumerHealth) succeeded(cookie []byte, now time.Time) {
	health.mu.Lock()
	health.state = "healthy"
	health.lastSuccess = now.UTC()
	health.degradedAt = time.Time{}
	health.lastError = ""
	if cookie != nil {
		health.cookie = bytes.Clone(cookie)
	}
	health.mu.Unlock()
}

func (health *syncConsumerHealth) waiting(err error, now time.Time) {
	health.mu.Lock()
	health.state = "retrying"
	health.retries++
	if health.degradedAt.IsZero() {
		health.degradedAt = now.UTC()
	}
	health.lastError = boundedSyncConsumerHealthError(err)
	health.mu.Unlock()
}

func (health *syncConsumerHealth) stopped(err error, now time.Time) {
	health.mu.Lock()
	health.state = "stopped"
	if health.degradedAt.IsZero() {
		health.degradedAt = now.UTC()
	}
	health.lastError = boundedSyncConsumerHealthError(err)
	health.mu.Unlock()
}

func (health *syncConsumerHealth) snapshot() syncConsumerHealthSnapshot {
	health.mu.RLock()
	defer health.mu.RUnlock()
	return syncConsumerHealthSnapshot{
		rid:         health.rid,
		partition:   health.partition,
		providers:   append([]string(nil), health.providers...),
		state:       health.state,
		provider:    health.provider,
		attempts:    health.attempts,
		retries:     health.retries,
		lastAttempt: health.lastAttempt,
		lastSuccess: health.lastSuccess,
		degradedAt:  health.degradedAt,
		lastError:   health.lastError,
		cookie:      bytes.Clone(health.cookie),
	}
}

func boundedSyncConsumerHealthError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.ToValidUTF8(err.Error(), "?")
	const maximum = 1024
	if len(value) > maximum {
		value = value[:maximum]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value
}

func (snapshot syncConsumerHealthSnapshot) monitorValues() []string {
	values := []string{
		"state=" + snapshot.state,
		"rid=" + fmt.Sprintf("%03d", snapshot.rid),
		"partition=" + snapshot.partition,
		"attempts=" + fmt.Sprintf("%d", snapshot.attempts),
		"retries=" + fmt.Sprintf("%d", snapshot.retries),
	}
	if snapshot.provider != "" {
		values = append(values, "provider="+snapshot.provider)
	}
	if !snapshot.lastAttempt.IsZero() {
		values = append(values, "lastAttempt="+monitorTime(snapshot.lastAttempt))
	}
	if !snapshot.lastSuccess.IsZero() {
		values = append(values, "lastSuccess="+monitorTime(snapshot.lastSuccess))
	}
	if !snapshot.degradedAt.IsZero() {
		values = append(values, "degradedSince="+monitorTime(snapshot.degradedAt))
	}
	if snapshot.lastError != "" {
		values = append(values, "lastError="+snapshot.lastError)
	}
	if len(snapshot.cookie) != 0 {
		digest := sha256.Sum256(snapshot.cookie)
		values = append(
			values,
			"cookieBytes="+fmt.Sprintf("%d", len(snapshot.cookie)),
			"cookieSHA256="+fmt.Sprintf("%x", digest[:]),
		)
	}
	for _, provider := range snapshot.providers {
		values = append(values, "configuredProvider="+provider)
	}
	return values
}

func sortSyncConsumerHealthSnapshots(values []syncConsumerHealthSnapshot) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].partition != values[j].partition {
			return values[i].partition < values[j].partition
		}
		return values[i].rid < values[j].rid
	})
}
