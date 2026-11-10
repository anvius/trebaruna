package pdffield

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/digitorus/pdf"
)

// fieldMDP is the signature reference a signature in a field with a lock
// dictionary carries (ISO 32000-1, 12.7.4.5 and 12.8.2.4): a FieldMDP
// transform over the catalogue whose parameters are the lock's, the
// fields it names and, from PDF 2.0, the changes still allowed (P). Empty
// for a field without a lock, or with one that names no action.
func fieldMDP(reader *pdf.Reader, field pdf.Value) string {
	lock := field.Key("Lock")
	action := lock.Key("Action").Name()
	if lock.Kind() != pdf.Dict || (action != "All" && action != "Include" && action != "Exclude") {
		return ""
	}
	parameters := "<< /Type /TransformParams /Action " + name(action)
	if action != "All" {
		parameters += " /Fields " + serialize(lock, lock.Key("Fields"), 0)
	}
	if permissions := lock.Key("P").Int64(); permissions >= 1 && permissions <= 3 {
		parameters += " /P " + strconv.FormatInt(permissions, 10)
	}
	parameters += " /V /1.2 >>"
	return "/Reference [<< /Type /SigRef /TransformMethod /FieldMDP /TransformParams " + parameters +
		" /Data " + reference(reader.Trailer().Key("Root")) + " >>]"
}

// lockedAgainst reports what earlier signatures' locks forbid: any change,
// when one allows none (PDF 2.0's FieldMDP P 1), or signing the field
// named, when one locked it. A new field is "".
func lockedAgainst(reader *pdf.Reader, field string) error {
	for _, locked := range fieldLocks(reader) {
		parameters := locked.Key("TransformParams")
		if parameters.Key("P").Int64() == 1 {
			return fmt.Errorf("%w: an earlier signer locked it against any change", ErrUnsupported)
		}
		if field != "" && locks(parameters, field) {
			return fmt.Errorf("%w: an earlier signature locked the field %q", ErrUnsupported, field)
		}
	}
	return nil
}

// LockedAgainstChanges reports a document an earlier signature locked
// against any change (PDF 2.0's FieldMDP P 1): no signature may follow.
func LockedAgainstChanges(reader *pdf.Reader) bool {
	return lockedAgainst(reader, "") != nil
}

// fieldLocks are the FieldMDP references of the document's signatures.
func fieldLocks(reader *pdf.Reader) []pdf.Value {
	var found []pdf.Value
	var visit func(fields pdf.Value, depth int)
	visit = func(fields pdf.Value, depth int) {
		for index := 0; index < fields.Len() && depth < 16; index++ {
			field := fields.Index(index)
			references := field.Key("V").Key("Reference")
			for position := 0; position < references.Len(); position++ {
				if references.Index(position).Key("TransformMethod").Name() == "FieldMDP" {
					found = append(found, references.Index(position))
				}
			}
			visit(field.Key("Kids"), depth+1)
		}
	}
	visit(reader.Trailer().Key("Root").Key("AcroForm").Key("Fields"), 0)
	return found
}

// locks reports whether a lock, or the FieldMDP parameters copied from
// one, covers the field: every field, the ones named and their
// descendants, or all but them.
func locks(parameters pdf.Value, field string) bool {
	named := false
	fields := parameters.Key("Fields")
	for index := 0; index < fields.Len(); index++ {
		name := fields.Index(index).Text()
		named = named || field == name || strings.HasPrefix(field, name+".")
	}
	switch parameters.Key("Action").Name() {
	case "All":
		return true
	case "Include":
		return named
	case "Exclude":
		return !named
	}
	return false
}

// lockedField is a field signing will make read-only, and the field flags
// it will carry: its own, or those it inherited, with ReadOnly set.
type lockedField struct {
	field pdf.Value
	flags int64
}

// readOnlyField is the ReadOnly field flag (ISO 32000-1, table 221).
const readOnlyField = 1

// lockedFields are the terminal fields the signing field's lock covers
// that are not read-only yet, the signing field aside: a reader is to keep
// them as they were signed (12.7.4.5), and the flag tells it so. A field
// written inside another object cannot be rewritten alone and stays as it
// is; the lock in the signature still names it.
func lockedFields(reader *pdf.Reader, signing pdf.Value) []lockedField {
	lock := signing.Key("Lock")
	var found []lockedField
	var visit func(fields pdf.Value, prefix string, inherited int64, depth int)
	visit = func(fields pdf.Value, prefix string, inherited int64, depth int) {
		for index := 0; index < fields.Len() && depth < 16; index++ {
			field := fields.Index(index)
			name := qualifiedName(prefix, field)
			flags := inherited
			if own := field.Key("Ff"); !own.IsNull() {
				flags = own.Int64()
			}
			if !terminal(field) {
				visit(field.Key("Kids"), name, flags, depth+1)
				continue
			}
			if field.GetPtr() != signing.GetPtr() && ownObject(field, fields) && flags&readOnlyField == 0 && locks(lock, name) {
				found = append(found, lockedField{field: field, flags: flags | readOnlyField})
			}
		}
	}
	visit(reader.Trailer().Key("Root").Key("AcroForm").Key("Fields"), "", 0, 0)
	return found
}
