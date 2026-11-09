package domain

// PINAction is what the person does to a card's PIN.
type PINAction string

const (
	// ChangePIN replaces the PIN, given the current one.
	ChangePIN PINAction = "change"
	// UnlockPIN sets a new PIN with the PUK, for a locked or forgotten PIN.
	UnlockPIN PINAction = "unlock"
	// ChangePUK replaces the PUK, given the current one; NewPIN and Repeat
	// then hold the new PUK.
	ChangePUK PINAction = "change-puk"
)

// PINChange is what the PIN dialog collects. The secrets travel to the
// command in its environment, never on its command line.
type PINChange struct {
	Action PINAction
	// Token is the card's label, empty when the only card present is meant.
	Token string
	// Secret is the current PIN (change) or the PUK (unlock, change-puk).
	Secret string
	NewPIN string
	Repeat string
}

// Validate refuses before the card is reached: an empty secret would be
// counted as a wrong one, and two new PINs that differ mean a typo the card
// would make permanent.
func (c PINChange) Validate() error {
	switch {
	case c.Secret == "" && (c.Action == UnlockPIN || c.Action == ChangePUK):
		return Problem{Code: ProblemMissingPUK}
	case c.Secret == "":
		return Problem{Code: ProblemMissingPIN}
	case c.NewPIN == "":
		return Problem{Code: ProblemNewPINRejected}
	case c.NewPIN != c.Repeat:
		return Problem{Code: ProblemPINMismatch}
	}
	return nil
}
