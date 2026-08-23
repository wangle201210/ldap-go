package auth

import (
	"errors"
	"strconv"
	"strings"
	"sync"
)

const (
	openLDAPCryptMaximumConcurrentDerivations = 8
	openLDAPCryptGlobalMemoryBudget           = 256 << 20
	openLDAPCryptCPUOnlyReservation           = 1 << 20
)

var ErrOpenLDAPCryptResourceLimit = errors.New("crypt resource budget exhausted")

type openLDAPCryptResourceController struct {
	mu                sync.Mutex
	maximumConcurrent int
	maximumMemory     int64
	active            int
	reservedMemory    int64
}

var globalOpenLDAPCryptResources = openLDAPCryptResourceController{
	maximumConcurrent: openLDAPCryptMaximumConcurrentDerivations,
	maximumMemory:     openLDAPCryptGlobalMemoryBudget,
}

func (controller *openLDAPCryptResourceController) tryAcquire(memory int64) (func(), bool) {
	if memory < 0 {
		return nil, false
	}
	controller.mu.Lock()
	if controller.active >= controller.maximumConcurrent ||
		memory > controller.maximumMemory-controller.reservedMemory {
		controller.mu.Unlock()
		return nil, false
	}
	controller.active++
	controller.reservedMemory += memory
	controller.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			controller.mu.Lock()
			controller.active--
			controller.reservedMemory -= memory
			controller.mu.Unlock()
		})
	}, true
}

func acquireOpenLDAPCryptResources(value string) (func(), error) {
	memory, expensive := openLDAPCryptResourceEstimate(value)
	if !expensive {
		return func() {}, nil
	}
	release, ok := globalOpenLDAPCryptResources.tryAcquire(memory)
	if !ok {
		return nil, ErrOpenLDAPCryptResourceLimit
	}
	return release, nil
}

func openLDAPCryptResourceEstimate(value string) (int64, bool) {
	switch {
	case strings.HasPrefix(value, "$y$"):
		return openLDAPYescryptMemoryEstimate(value)
	case strings.HasPrefix(value, "$sm3y$"):
		return openLDAPNationalYescryptMemoryEstimate(value, "sm3y")
	case strings.HasPrefix(value, "$gy$"):
		return openLDAPNationalYescryptMemoryEstimate(value, "gy")
	case strings.HasPrefix(value, "$7$"):
		return openLDAPScryptMemoryEstimate(value)
	case strings.HasPrefix(value, "$2"),
		strings.HasPrefix(value, "$5$"),
		strings.HasPrefix(value, "$6$"),
		strings.HasPrefix(value, "$sm3$"),
		strings.HasPrefix(value, "_"),
		strings.HasPrefix(value, "$sha1$"),
		strings.HasPrefix(value, "$md5"):
		return openLDAPCryptCPUOnlyReservation, true
	default:
		return 0, false
	}
}

func openLDAPYescryptMemoryEstimate(value string) (int64, bool) {
	parts := strings.Split(value, "$")
	if len(parts) < 4 || parts[0] != "" || parts[1] != "y" ||
		len(parts[2]) != 3 || parts[2][0] != 'j' {
		return openLDAPCryptCPUOnlyReservation, true
	}
	nLog, err := openLDAPCrypt64Value(parts[2][1])
	if err != nil || nLog > 18 {
		return openLDAPCryptCPUOnlyReservation, true
	}
	r, err := openLDAPCrypt64Value(parts[2][2])
	if err != nil {
		return openLDAPCryptCPUOnlyReservation, true
	}
	n := uint64(1) << (nLog + 1)
	memory := n * (r + 1) * 128
	if memory > uint64(MaxOpenLDAPCryptMemoryBytes) {
		memory = uint64(MaxOpenLDAPCryptMemoryBytes)
	}
	return int64(memory), true
}

func openLDAPNationalYescryptMemoryEstimate(value, identifier string) (int64, bool) {
	parts := strings.Split(value, "$")
	if len(parts) < 4 || parts[0] != "" || parts[1] != identifier {
		return openLDAPCryptCPUOnlyReservation, true
	}
	return openLDAPYescryptMemoryEstimate("$y$" + parts[2] + "$" + parts[3])
}

func openLDAPScryptMemoryEstimate(value string) (int64, bool) {
	body := strings.TrimPrefix(value, "$7$")
	if separator := strings.IndexByte(body, '$'); separator >= 0 {
		body = body[:separator]
	}
	if len(body) < 11 {
		return openLDAPCryptCPUOnlyReservation, true
	}
	nLog, err := openLDAPCrypt64Value(body[0])
	if err != nil || nLog > 30 {
		return openLDAPCryptCPUOnlyReservation, true
	}
	r, err := decodeOpenLDAPCryptUint30(body[1:6])
	if err != nil {
		return openLDAPCryptCPUOnlyReservation, true
	}
	memory := (uint64(1) << nLog) * uint64(r) * 128
	if memory > uint64(MaxOpenLDAPCryptMemoryBytes) {
		memory = uint64(MaxOpenLDAPCryptMemoryBytes)
	}
	return int64(memory), true
}

func recognizedOpenLDAPCryptSetting(setting string) bool {
	switch {
	case len(setting) == 2 && validOpenLDAPCryptString(setting):
		return true
	case strings.HasPrefix(setting, "$1$"):
		_, err := parseOpenLDAPCryptSetting(setting)
		return err == nil
	case strings.HasPrefix(setting, "$2"),
		strings.HasPrefix(setting, "$5$"),
		strings.HasPrefix(setting, "$6$"):
		_, err := parseOpenLDAPCryptSetting(setting)
		return err == nil
	case strings.HasPrefix(setting, "$y$"):
		parts := strings.Split(setting, "$")
		if len(parts) != 4 || len(parts[2]) != 3 || parts[2][0] != 'j' {
			return false
		}
		_, errN := openLDAPCrypt64Value(parts[2][1])
		_, errR := openLDAPCrypt64Value(parts[2][2])
		return errN == nil && errR == nil && parts[3] != ""
	case strings.HasPrefix(setting, "$7$"):
		body := strings.TrimPrefix(setting, "$7$")
		return len(body) >= 12 && !strings.ContainsRune(body, '$')
	case strings.HasPrefix(setting, "_"):
		return len(setting) == 9
	case strings.HasPrefix(setting, "$sha1$"):
		parts := strings.Split(setting, "$")
		if len(parts) != 4 || parts[2] == "" || parts[3] == "" {
			return false
		}
		_, err := strconv.ParseUint(parts[2], 10, 32)
		return err == nil
	case strings.HasPrefix(setting, "$md5"):
		return strings.Count(setting, "$") >= 2
	case setting == "$3$":
		return true
	case strings.HasPrefix(setting, "$sm3$"),
		strings.HasPrefix(setting, "$sm3y$"),
		strings.HasPrefix(setting, "$gy$"):
		return strings.Count(setting, "$") >= 3
	case len(setting) > 13 && setting[0] != '$' && validOpenLDAPCryptString(setting):
		return true
	default:
		return false
	}
}
