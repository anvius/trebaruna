package domain

import (
	"maps"
	"strconv"
	"strings"
)

// SealWanted reads visibleSignature: "want", the person places the seal on
// the page, or "optional", they may; empty when the page fixed the seal's
// place itself (signaturePositionOnPage…, signatureField) or asked nothing.
func SealWanted(properties map[string]string) string {
	wanted := strings.ToLower(strings.TrimSpace(properties["visibleSignature"]))
	if wanted != "want" && wanted != "optional" {
		return ""
	}
	if strings.TrimSpace(properties["signatureField"]) != "" || strings.TrimSpace(properties["signaturePositionOnPageLowerLeftX"]) != "" {
		return ""
	}
	return wanted
}

// SealBox is the place the person chose for the seal, in PDF points on a
// page counted from 1.
type SealBox struct {
	Page                                             int
	LowerLeftX, LowerLeftY, UpperRightX, UpperRightY float64
}

// IsZero reports no place chosen.
func (b SealBox) IsZero() bool { return b.Page == 0 && b.UpperRightX == 0 && b.UpperRightY == 0 }

// Into returns the properties with the box as AutoFirma's position
// parameters, which the PDF signature reads; the page's map is not touched.
func (b SealBox) Into(properties map[string]string) map[string]string {
	placed := maps.Clone(properties)
	if placed == nil {
		placed = map[string]string{}
	}
	number := func(value float64) string { return strconv.FormatFloat(value, 'f', -1, 64) }
	placed["signaturePage"] = strconv.Itoa(b.Page)
	placed["signaturePositionOnPageLowerLeftX"] = number(b.LowerLeftX)
	placed["signaturePositionOnPageLowerLeftY"] = number(b.LowerLeftY)
	placed["signaturePositionOnPageUpperRightX"] = number(b.UpperRightX)
	placed["signaturePositionOnPageUpperRightY"] = number(b.UpperRightY)
	return placed
}
