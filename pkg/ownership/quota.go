package ownership

import "fmt"

// QuotaError is a declaration refused for being larger than the plugin's
// quota.
//
// It reports Denied so the runtime maps it to the status a plugin can act
// on: a plugin told its set was too large can narrow it, where one told
// the host failed can only give up. That distinction is the whole reason
// the guest sees two different statuses.
type QuotaError struct {
	What     string
	Declared int
	Quota    int
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("%s: %d declared, quota %d", e.What, e.Declared, e.Quota)
}

// Denied marks this as a policy refusal rather than a host failure.
func (e *QuotaError) Denied() bool { return true }
