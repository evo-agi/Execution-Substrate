package reliablesubmit

import "time"

type claimClock interface {
	Now() time.Time
}

type systemClaimClock struct{}

func (systemClaimClock) Now() time.Time {
	return normalizeClaimTime(time.Now())
}

type fixedClaimClock struct {
	now time.Time
}

func (c fixedClaimClock) Now() time.Time {
	return normalizeClaimTime(c.now)
}

func normalizeClaimTime(t time.Time) time.Time {
	return t.UTC().Round(0)
}

type optionalClaimTime struct {
	value time.Time
	valid bool
}

func someClaimTime(t time.Time) optionalClaimTime {
	return optionalClaimTime{value: normalizeClaimTime(t), valid: true}
}

func noClaimTime() optionalClaimTime {
	return optionalClaimTime{}
}

func claimTimeFromUnixNano(value int64) optionalClaimTime {
	if value == 0 {
		return noClaimTime()
	}
	return someClaimTime(time.Unix(0, value))
}

func (t optionalClaimTime) unixNano() int64 {
	if !t.valid {
		return 0
	}
	return normalizeClaimTime(t.value).UnixNano()
}

func (t optionalClaimTime) equal(other optionalClaimTime) bool {
	if t.valid != other.valid {
		return false
	}
	if !t.valid {
		return true
	}
	return normalizeClaimTime(t.value).Equal(normalizeClaimTime(other.value))
}
