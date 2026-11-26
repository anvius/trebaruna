package domain_test

import (
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// TestOnlyAnAnswerThePageReceivedEndsTheRequest: the window closes once the
// page has its answer, signed or CANCEL; a failure the page heard, or one
// that never reached it, leaves the window open with the error.
func TestOnlyAnAnswerThePageReceivedEndsTheRequest(t *testing.T) {
	cases := []struct {
		name      string
		outcome   domain.PageOutcome
		answered  bool
		succeeded bool
	}{
		{"signed and delivered", domain.PageOutcome{Answer: "Y2VydA==|c2ln", Delivered: true}, true, true},
		{"signed, not delivered", domain.PageOutcome{Answer: "Y2VydA==|c2ln"}, false, false},
		{"declined and delivered", domain.PageOutcome{Answer: "CANCEL", Delivered: true}, true, false},
		{"declined, not delivered", domain.PageOutcome{Answer: "CANCEL"}, false, false},
		{"a failure the page heard", domain.PageOutcome{Answer: "SAF_06: formato no soportado", Delivered: true}, false, false},
		{"an error after the answer", domain.PageOutcome{Answer: "Y2VydA==|c2ln", Error: "the card was removed", Delivered: true}, false, false},
		{"nothing answered", domain.PageOutcome{Delivered: true}, false, false},
	}
	for _, entry := range cases {
		if got := entry.outcome.Answered(); got != entry.answered {
			t.Errorf("%s: Answered() = %t, want %t", entry.name, got, entry.answered)
		}
		if got := entry.outcome.Succeeded(); got != entry.succeeded {
			t.Errorf("%s: Succeeded() = %t, want %t", entry.name, got, entry.succeeded)
		}
	}
}
