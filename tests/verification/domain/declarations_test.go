package domain_test

import (
	"testing"

	"codeberg.org/simplicer/trebaruna/src/verification/domain"
)

func TestADeclaredPolicyIsNamedWhenKnown(t *testing.T) {
	for identifier, want := range map[string][2]string{
		"urn:oid:2.16.724.1.3.1.1.2.1.9": {"AGE 1.9", "AGE 1.9 (2.16.724.1.3.1.1.2.1.9)"},
		"2.16.724.1.3.1.1.2.1.8":         {"AGE 1.8", "AGE 1.8 (2.16.724.1.3.1.1.2.1.8)"},
		"1.2.3.4":                        {"", "1.2.3.4"},
	} {
		declared := domain.Declarations{Policy: identifier}
		if declared.PolicyName() != want[0] || declared.PolicyText() != want[1] || declared.Empty() {
			t.Errorf("%s: %q, %q", identifier, declared.PolicyName(), declared.PolicyText())
		}
	}
	if !(domain.Declarations{}).Empty() || (domain.Declarations{Place: "Roma"}).Empty() {
		t.Error("Empty")
	}
}
