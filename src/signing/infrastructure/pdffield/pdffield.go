// Package pdffield signs a PDF in a signature field it already has: a form
// prepared with an empty field for each signer, where the signature must
// go. The PDF library trebaruna signs with always adds a field of its own.
//
// The signature is an incremental update (ISO 32000-1, 7.5.6) that leaves
// every byte before it intact: the signature dictionary, the field with its
// value (/V) and its appearance (/AP), the appearance's objects, the form's
// /SigFlags when they must change, and a cross-reference section of the
// kind the file already uses (a table, or a stream).
package pdffield

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/digitorus/pdf"
)

var (
	// ErrNoSuchField means the document has no empty signature field of that
	// name.
	ErrNoSuchField = errors.New("no empty signature field of that name")
	// ErrUnsupported means the document is one this package does not update:
	// encrypted, or certified against any change.
	ErrUnsupported = errors.New("this PDF cannot be signed in an existing field")
)

// Field is an empty signature field.
type Field struct {
	// Name is the fully qualified field name: the partial names of the
	// field and its ancestors, joined by dots.
	Name string
	// Page is the page its widget is on, from 1; 0 when unknown.
	Page int
	// Rect is the widget's rectangle: lower left x, y, upper right x, y.
	Rect [4]float64

	field, widget pdf.Value
}

// Width and Height are the size of the widget, in points.
func (f Field) Width() float64  { return abs(f.Rect[2] - f.Rect[0]) }
func (f Field) Height() float64 { return abs(f.Rect[3] - f.Rect[1]) }

// Appearance is what the widget shows: a form XObject's content stream and
// resources (a PDF dictionary, written as is), and the objects the
// resources refer to as {{0}}, {{1}}…, written as new objects.
type Appearance struct {
	Content   []byte
	Resources string
	Objects   []Object
}

// Object is a new PDF object: a dictionary and, for a stream, its data.
// {{n}} in the dictionary refers to the n-th object of the appearance.
type Object struct {
	Dictionary string
	Stream     []byte
}

// Signature describes the signature dictionary.
type Signature struct {
	// Name, Reason and Location are written when not empty.
	Name, Reason, Location string
	// Password opens an encrypted document: its user or owner password;
	// empty tries the empty user password, as documents that only restrict
	// permissions have.
	Password string
	// SignedAt is /M.
	SignedAt time.Time
	// Reserve is the room for the CMS envelope, in bytes.
	Reserve int
	// Envelope builds the CMS envelope over the bytes the signature covers.
	Envelope func(signed []byte) ([]byte, error)
}

// ErrReserveTooSmall means the envelope did not fit in Signature.Reserve.
var ErrReserveTooSmall = errors.New("the signature does not fit in the room reserved for it")

// EmptyFields lists the document's empty signature fields.
func EmptyFields(content []byte) ([]Field, error) {
	reader, err := pdf.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("read the PDF: %w", err)
	}
	return emptyFields(reader), nil
}

func emptyFields(reader *pdf.Reader) []Field {
	pages := pageNumbers(reader)
	var found []Field
	var visit func(fields pdf.Value, prefix, inheritedType string, depth int)
	visit = func(fields pdf.Value, prefix, inheritedType string, depth int) {
		if depth > 16 {
			return
		}
		for index := 0; index < fields.Len(); index++ {
			field := fields.Index(index)
			name := prefix
			if partial := field.Key("T").Text(); partial != "" {
				name = strings.TrimPrefix(prefix+"."+partial, ".")
			}
			fieldType := inheritedType
			if own := field.Key("FT").Name(); own != "" {
				fieldType = own
			}
			kids := field.Key("Kids")
			if terminal(field) {
				if fieldType == "Sig" && field.Key("V").IsNull() {
					if widget, ok := widgetOf(field); ok {
						found = append(found, Field{Name: name, Page: pages[widget.Key("P").GetPtr()],
							Rect: rectangle(widget.Key("Rect")), field: field, widget: widget})
					}
				}
				continue
			}
			visit(kids, name, fieldType, depth+1)
		}
	}
	visit(reader.Trailer().Key("Root").Key("AcroForm").Key("Fields"), "", "", 0)
	return found
}

// terminal reports a field whose kids, if any, are only its widgets.
func terminal(field pdf.Value) bool {
	kids := field.Key("Kids")
	for index := 0; index < kids.Len(); index++ {
		if !kids.Index(index).Key("T").IsNull() || kids.Index(index).Key("Subtype").Name() != "Widget" {
			return false
		}
	}
	return true
}

// widgetOf is the field's one widget: the field itself when they are
// merged, or its only kid.
func widgetOf(field pdf.Value) (pdf.Value, bool) {
	if field.Key("Subtype").Name() == "Widget" || field.Key("Kids").IsNull() {
		return field, true
	}
	if kids := field.Key("Kids"); kids.Len() == 1 {
		return kids.Index(0), true
	}
	return pdf.Value{}, false
}

// pageNumbers maps each page object to its number.
func pageNumbers(reader *pdf.Reader) map[pdf.Ptr]int {
	numbers := map[pdf.Ptr]int{}
	for number := 1; number <= reader.NumPage(); number++ {
		numbers[reader.Page(number).V.GetPtr()] = number
	}
	return numbers
}

func rectangle(value pdf.Value) [4]float64 {
	var rect [4]float64
	for index := 0; index < 4 && index < value.Len(); index++ {
		rect[index] = value.Index(index).Float64()
	}
	return rect
}

func abs(value float64) float64 {
	if value < 0 {
		return -value
	}
	return value
}

// Sign signs the document in its empty signature field called name.
func Sign(content []byte, name string, appearance *Appearance, signature Signature) ([]byte, error) {
	reader, err := openForSigning(content, signature.Password)
	if err != nil {
		return nil, err
	}
	fields := emptyFields(reader)
	index := slices.IndexFunc(fields, func(field Field) bool { return field.Name == name })
	if index < 0 {
		return nil, missingField(name, fields)
	}
	field := fields[index]

	update, err := newUpdate(content, reader)
	if err != nil {
		return nil, err
	}
	signatureID := update.allocate()
	widgetChanges := map[string]string{}
	if appearance != nil {
		widgetChanges["AP"] = fmt.Sprintf("<< /N %d 0 R >>", update.writeAppearance(field.Width(), field.Height(), appearance))
		if field.widget.Key("F").IsNull() {
			widgetChanges["F"] = "4" // printed
		}
	}
	fieldChanges := map[string]string{"V": fmt.Sprintf("%d 0 R", signatureID)}
	if field.field.GetPtr() == field.widget.GetPtr() {
		maps.Copy(fieldChanges, widgetChanges)
	} else if len(widgetChanges) > 0 {
		if err := update.rewrite(field.widget, widgetChanges); err != nil {
			return nil, err
		}
	}
	if err := update.rewrite(field.field, fieldChanges); err != nil {
		return nil, err
	}
	if err := update.markSigned(reader); err != nil {
		return nil, err
	}

	update.signaturePlaceholder(signatureID, signature)
	return update.finish(signatureID, signature)
}

// missingField says the field is not there, and which ones are.
func missingField(name string, fields []Field) error {
	if len(fields) == 0 {
		return fmt.Errorf("%w: %q (the document has none)", ErrNoSuchField, name)
	}
	names := make([]string, len(fields))
	for position, field := range fields {
		names[position] = field.Name
	}
	return fmt.Errorf("%w: %q (empty ones: %s)", ErrNoSuchField, name, strings.Join(names, ", "))
}

// writeAppearance writes the appearance as a form XObject of the widget's
// size, with its objects, and returns the form's number.
func (u *update) writeAppearance(width, height float64, appearance *Appearance) uint32 {
	formID := u.allocate()
	ids := make([]uint32, len(appearance.Objects))
	for position := range appearance.Objects {
		ids[position] = u.allocate()
	}
	u.write(formID, fmt.Sprintf("<< /Type /XObject /Subtype /Form /BBox [0 0 %s %s] /Resources %s /Length %d >>",
		number(width), number(height), references(appearance.Resources, ids), len(appearance.Content)), appearance.Content)
	for position, object := range appearance.Objects {
		dictionary := references(object.Dictionary, ids)
		if object.Stream != nil {
			dictionary = strings.TrimSuffix(strings.TrimSpace(dictionary), ">>") + fmt.Sprintf(" /Length %d >>", len(object.Stream))
		}
		u.write(ids[position], dictionary, object.Stream)
	}
	return formID
}

// ErrPasswordNeeded means the document is encrypted and the password given
// does not open it.
var ErrPasswordNeeded = errors.New("the PDF is encrypted and this password does not open it")

// openForSigning reads a PDF this package can add a signature to: opened
// with its password when encrypted, its author's permissions allowing a
// signature, and not certified against any change.
func openForSigning(content []byte, password string) (*pdf.Reader, error) {
	given := false
	reader, err := pdf.NewReaderEncrypted(bytes.NewReader(content), int64(len(content)), func() string {
		// Asked once: a second call means the password failed.
		if given {
			return ""
		}
		given = true
		return password
	})
	if errors.Is(err, pdf.ErrInvalidPassword) {
		return nil, ErrPasswordNeeded
	}
	if err != nil {
		return nil, fmt.Errorf("read the PDF: %w", err)
	}
	if reader.IsEncrypted() && !SigningPermitted(reader) {
		return nil, fmt.Errorf("%w: its author's permissions allow neither filling in forms nor signing", ErrUnsupported)
	}
	if certifiedAgainstChanges(reader) {
		return nil, fmt.Errorf("%w: its author certified it against any change", ErrUnsupported)
	}
	return reader, nil
}

// SigningPermitted reads an encrypted document's permissions (/P): a
// signature needs bit 9, filling in form fields, or bit 6, changing
// annotations and filling in forms (ISO 32000-1, table 22).
func SigningPermitted(reader *pdf.Reader) bool {
	permissions := reader.Trailer().Key("Encrypt").Key("P").Int64()
	return permissions&(1<<8) != 0 || permissions&(1<<5) != 0
}

// certifiedAgainstChanges reports a certification signature whose DocMDP
// permissions (P 1) forbid any change, a signature included.
func certifiedAgainstChanges(reader *pdf.Reader) bool {
	docMDP := reader.Trailer().Key("Root").Key("Perms").Key("DocMDP")
	references := docMDP.Key("Reference")
	for index := 0; index < references.Len(); index++ {
		reference := references.Index(index)
		if reference.Key("TransformMethod").Name() == "DocMDP" {
			permissions := reference.Key("TransformParams").Key("P")
			return !permissions.IsNull() && permissions.Int64() == 1
		}
	}
	return false
}

// references replaces {{n}} with the n-th new object's reference.
func references(text string, ids []uint32) string {
	for position, id := range ids {
		text = strings.ReplaceAll(text, fmt.Sprintf("{{%d}}", position), fmt.Sprintf("%d 0 R", id))
	}
	return text
}

// update is an incremental update being written after the original bytes.
type update struct {
	original []byte
	reader   *pdf.Reader
	// signatureID is the signature dictionary, whose /Contents stays
	// unencrypted; err is the first failure to encrypt an object.
	signatureID uint32
	err         error
	body        bytes.Buffer
	offsets     map[uint32]int64
	gens        map[uint32]int
	size        uint32
	stream      bool
	previous    int64
}

func newUpdate(original []byte, reader *pdf.Reader) (*update, error) {
	trailer := reader.Trailer()
	previous, err := lastStartXref(original)
	if err != nil {
		return nil, err
	}
	u := &update{
		original: original,
		reader:   reader,
		offsets:  map[uint32]int64{},
		gens:     map[uint32]int{},
		size:     uint32(trailer.Key("Size").Int64()),
		stream:   reader.XrefInformation.Type == "stream",
		previous: previous,
	}
	if u.size == 0 {
		return nil, fmt.Errorf("%w: its trailer has no /Size", ErrUnsupported)
	}
	if !bytes.HasSuffix(original, []byte("\n")) && !bytes.HasSuffix(original, []byte("\r")) {
		u.body.WriteString("\n")
	}
	return u, nil
}

// lastStartXref reads the offset after the file's last startxref.
func lastStartXref(content []byte) (int64, error) {
	at := bytes.LastIndex(content, []byte("startxref"))
	if at < 0 {
		return 0, fmt.Errorf("%w: no startxref", ErrUnsupported)
	}
	var offset int64
	if _, err := fmt.Sscan(string(content[at+len("startxref"):min(len(content), at+len("startxref")+32)]), &offset); err != nil {
		return 0, fmt.Errorf("%w: unreadable startxref", ErrUnsupported)
	}
	return offset, nil
}

// allocate reserves the number of a new object.
func (u *update) allocate() uint32 {
	id := u.size
	u.size++
	return id
}

// position is where the next byte of the update lands in the file.
func (u *update) position() int64 {
	return int64(len(u.original) + u.body.Len())
}

// write appends an object, a stream when data is not nil.
func (u *update) write(id uint32, dictionary string, data []byte) {
	u.writeWithGeneration(id, 0, dictionary, data)
}

func (u *update) writeWithGeneration(id uint32, generation int, dictionary string, data []byte) {
	if u.reader.IsEncrypted() {
		var err error
		if dictionary, data, err = encryptObject(u.reader, id, generation, dictionary, data, id == u.signatureID); err != nil && u.err == nil {
			u.err = err
		}
	}
	u.offsets[id], u.gens[id] = u.position(), generation
	fmt.Fprintf(&u.body, "%d %d obj\n%s\n", id, generation, dictionary)
	if data != nil {
		u.body.WriteString("stream\n")
		u.body.Write(data)
		u.body.WriteString("\nendstream\n")
	}
	u.body.WriteString("endobj\n")
}

// rewrite writes an existing object again, its entries changed or added.
func (u *update) rewrite(object pdf.Value, changes map[string]string) error {
	pointer := object.GetPtr()
	if pointer.GetID() == 0 || object.Kind() != pdf.Dict {
		return fmt.Errorf("%w: the field is not an object of its own", ErrUnsupported)
	}
	u.writeWithGeneration(pointer.GetID(), int(pointer.GetGen()), dictionaryWith(object, changes), nil)
	return nil
}

// markSigned sets /SigFlags 3 (signatures exist, append only) on the form.
func (u *update) markSigned(reader *pdf.Reader) error {
	root := reader.Trailer().Key("Root")
	form := root.Key("AcroForm")
	if form.Key("SigFlags").Int64()&3 == 3 {
		return nil
	}
	if form.GetPtr() != root.GetPtr() {
		return u.rewrite(form, map[string]string{"SigFlags": "3"})
	}
	return u.rewrite(root, map[string]string{"AcroForm": dictionaryWith(form, map[string]string{"SigFlags": "3"})})
}

// byteRangeMarker reserves room for /ByteRange, filled once the file is
// complete.
const byteRangeMarker = "/ByteRange [0 0000000000 0000000000 0000000000]"

// signaturePlaceholder writes the signature dictionary, its /Contents a
// run of zeros as long as the room reserved for the envelope.
func (u *update) signaturePlaceholder(id uint32, signature Signature) {
	var dictionary strings.Builder
	dictionary.WriteString("<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached ")
	dictionary.WriteString(byteRangeMarker)
	fmt.Fprintf(&dictionary, " /Contents <%s>", strings.Repeat("0", 2*reserveOf(signature)))
	fmt.Fprintf(&dictionary, " /M %s", pdfString(pdfDate(signature.SignedAt)))
	for _, entry := range [][2]string{{"Name", signature.Name}, {"Reason", signature.Reason}, {"Location", signature.Location}} {
		if entry[1] != "" {
			fmt.Fprintf(&dictionary, " /%s %s", entry[0], pdfString(entry[1]))
		}
	}
	dictionary.WriteString(" >>")
	u.signatureID = id
	u.write(id, dictionary.String(), nil)
}

func reserveOf(signature Signature) int {
	if signature.Reserve <= 0 {
		return 16384
	}
	return signature.Reserve
}

// finish writes the cross-reference section and the trailer, then signs
// every byte of the file but the signature's own /Contents.
func (u *update) finish(signatureID uint32, signature Signature) ([]byte, error) {
	if u.err != nil {
		return nil, fmt.Errorf("encrypt the update: %w", u.err)
	}
	if err := u.crossReferences(); err != nil {
		return nil, err
	}
	signed := append(append([]byte{}, u.original...), u.body.Bytes()...)

	object := u.offsets[signatureID]
	open := bytes.Index(signed[object:], []byte("/Contents <"))
	if open < 0 {
		return nil, fmt.Errorf("the signature dictionary was not written")
	}
	start := object + int64(open) + int64(len("/Contents "))
	end := start + int64(2*reserveOf(signature)) + 2
	byteRange := fmt.Sprintf("/ByteRange [0 %d %d %d]", start, end, int64(len(signed))-end)
	if len(byteRange) > len(byteRangeMarker) {
		return nil, fmt.Errorf("%w: the document is too large", ErrUnsupported)
	}
	at := object + int64(bytes.Index(signed[object:], []byte(byteRangeMarker)))
	copy(signed[at:], byteRange+strings.Repeat(" ", len(byteRangeMarker)-len(byteRange)))

	covered := append(append([]byte{}, signed[:start]...), signed[end:]...)
	envelope, err := signature.Envelope(covered)
	if err != nil {
		return nil, err
	}
	if len(envelope) > reserveOf(signature) {
		return nil, ErrReserveTooSmall
	}
	copy(signed[start+1:], fmt.Sprintf("%X", envelope))
	return signed, nil
}

// crossReferences writes the update's cross-reference section, of the kind
// the file uses, and the trailer.
func (u *update) crossReferences() error {
	trailer := u.reader.Trailer()
	var common strings.Builder
	fmt.Fprintf(&common, "/Root %s", reference(trailer.Key("Root")))
	if info := trailer.Key("Info"); !info.IsNull() {
		fmt.Fprintf(&common, " /Info %s", reference(info))
	}
	if encrypt := trailer.Key("Encrypt"); !encrypt.IsNull() {
		// The update is encrypted as the document is, under the same
		// dictionary.
		fmt.Fprintf(&common, " /Encrypt %s", reference(encrypt))
	}
	if id := trailer.Key("ID"); id.Len() == 2 {
		fmt.Fprintf(&common, " /ID [%s %s]", pdfString(id.Index(0).RawString()), pdfString(id.Index(1).RawString()))
	}
	fmt.Fprintf(&common, " /Prev %d", u.previous)

	if !u.stream {
		start := u.position()
		u.body.WriteString("xref\n")
		for _, run := range runs(u.sortedIDs()) {
			fmt.Fprintf(&u.body, "%d %d\n", run[0], len(run))
			for _, id := range run {
				fmt.Fprintf(&u.body, "%010d %05d n\r\n", u.offsets[id], u.gens[id])
			}
		}
		fmt.Fprintf(&u.body, "trailer\n<< /Size %d %s >>\nstartxref\n%d\n%%%%EOF\n", u.size, common.String(), start)
		return nil
	}

	// A cross-reference stream (ISO 32000-1, 7.5.8), itself the last new
	// object: entries of type 1, 4-byte offsets, uncompressed.
	streamID := u.allocate()
	start := u.position()
	u.offsets[streamID], u.gens[streamID] = start, 0
	var entries bytes.Buffer
	var index strings.Builder
	for _, run := range runs(u.sortedIDs()) {
		fmt.Fprintf(&index, "%d %d ", run[0], len(run))
		for _, id := range run {
			offset, generation := u.offsets[id], u.gens[id]
			if offset > 0xFFFFFFFF {
				return fmt.Errorf("%w: the document is too large", ErrUnsupported)
			}
			entries.Write([]byte{1, byte(offset >> 24), byte(offset >> 16), byte(offset >> 8), byte(offset), byte(generation >> 8), byte(generation)})
		}
	}
	fmt.Fprintf(&u.body, "%d 0 obj\n<< /Type /XRef /Size %d /Index [%s] /W [1 4 2] %s /Length %d >>\nstream\n",
		streamID, u.size, strings.TrimSpace(index.String()), common.String(), entries.Len())
	u.body.Write(entries.Bytes())
	fmt.Fprintf(&u.body, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", start)
	return nil
}

// sortedIDs are the numbers of the objects written, in order.
func (u *update) sortedIDs() []uint32 {
	ids := make([]uint32, 0, len(u.offsets))
	for id := range u.offsets {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// runs splits sorted ids into runs of consecutive numbers.
func runs(ids []uint32) [][]uint32 {
	var result [][]uint32
	for _, id := range ids {
		if last := len(result) - 1; last >= 0 && result[last][len(result[last])-1]+1 == id {
			result[last] = append(result[last], id)
			continue
		}
		result = append(result, []uint32{id})
	}
	return result
}

// pdfDate is a PDF date (ISO 32000-1, 7.9.4).
func pdfDate(moment time.Time) string {
	if moment.IsZero() {
		moment = time.Now()
	}
	_, offset := moment.Zone()
	sign := '+'
	if offset < 0 {
		sign, offset = '-', -offset
	}
	return fmt.Sprintf("D:%s%c%02d'%02d'", moment.Format("20060102150405"), sign, offset/3600, offset%3600/60)
}
