package domain

// ProductionPlace is where a signature says it was made (XAdES
// SignatureProductionPlace): a statement of the signer, covered by the
// signature.
type ProductionPlace struct {
	City, Province, PostalCode, Country string
}

// IsZero reports a place that says nothing.
func (p ProductionPlace) IsZero() bool {
	return p == ProductionPlace{}
}
