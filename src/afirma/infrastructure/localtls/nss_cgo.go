//go:build cgo

package localtls

// #include <stdlib.h>
import "C"

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/miekg/pkcs11"

	signinfra "codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// The store is written through softokn3's PKCS#11 interface, the library that
// Firefox and certutil use, so no NSS tool has to be installed. NSS keeps a root
// as two objects, the certificate and a trust object saying what it is trusted
// for, as certutil -A -t "C,," does. Their types are NSS's vendor extensions,
// and the values are those of NSS's own headers (nss/pkcs11n.h, NSCP vendor).
const (
	vendorDefined = 0x80000000
	nssVendor     = 0x4E534350

	ckoNSSTrust = (vendorDefined | nssVendor) + 3 // CKO_NSS_TRUST

	ckaNSS                  = vendorDefined | nssVendor // CKA_NSS
	ckaNSSTrust             = ckaNSS + 0x2000           // CKA_TRUST
	ckaTrustServerAuth      = ckaNSSTrust + 8           // CKA_TRUST_SERVER_AUTH
	ckaTrustEmailProtection = ckaNSSTrust + 11          // CKA_TRUST_EMAIL_PROTECTION
	ckaTrustCodeSigning     = ckaNSSTrust + 10          // CKA_TRUST_CODE_SIGNING
	ckaCertSHA1Hash         = ckaNSSTrust + 100         // CKA_CERT_SHA1_HASH
	ckaCertMD5Hash          = ckaNSSTrust + 101         // CKA_CERT_MD5_HASH

	cktNSS                 = vendorDefined | nssVendor // CKT_NSS
	cktNSSTrustedDelegator = cktNSS + 2                // CKT_NSS_TRUSTED_DELEGATOR
	cktNSSTrustUnknown     = cktNSS + 5                // CKT_NSS_TRUST_UNKNOWN
)

// nssCertificateToken is the token label of a store's certificates and trust.
const nssCertificateToken = "NSS Certificate DB"

// available reports whether softokn3 is there to open a store with.
func available() bool {
	return signinfra.NSSModule() != ""
}

// nssToken is one NSS store open through softokn3's PKCS#11 interface.
type nssToken struct {
	context *pkcs11.Ctx
	handle  pkcs11.SessionHandle
}

// openToken opens a store, read-only unless writable, and logs in with the
// empty PIN a store without a master password has. A store with one is refused,
// so it reads as one that cannot be checked.
func openToken(database string, writable bool) (*nssToken, error) {
	token, err := openSession(database, writable)
	if err != nil {
		return nil, err
	}
	// The trust objects are readable and writable only by a logged-in session.
	if err := token.login(); err != nil {
		token.close()
		return nil, fmt.Errorf("cannot log in to the store %s, which needs a master password trebaruna does not enter: %w", database, err)
	}
	return token, nil
}

// openSession opens a store's certificate token without logging in.
func openSession(database string, writable bool) (*nssToken, error) {
	module := signinfra.NSSModule()
	if module == "" {
		return nil, ErrNoNSS
	}
	parameters := signinfra.SoftwareStore{Directory: database}.Parameters()
	if writable {
		parameters = strings.TrimSuffix(parameters, " flags=readOnly")
	}
	context := pkcs11.New(module)
	if context == nil {
		return nil, fmt.Errorf("cannot load %s", module)
	}
	reserved := C.CString(parameters)
	defer C.free(unsafe.Pointer(reserved))
	// A library another part of this process already initialised holds another
	// store: it is refused rather than used for this one.
	if err := context.Initialize(pkcs11.InitializeWithReserved(unsafe.Pointer(reserved))); err != nil {
		context.Destroy()
		return nil, fmt.Errorf("cannot open the store %s: %w", database, err)
	}
	slot, err := certificateSlot(context)
	if err != nil {
		release(context)
		return nil, fmt.Errorf("the store %s: %w", database, err)
	}
	flags := uint(pkcs11.CKF_SERIAL_SESSION)
	if writable {
		flags |= pkcs11.CKF_RW_SESSION
	}
	handle, err := context.OpenSession(slot, flags)
	if err != nil {
		release(context)
		return nil, fmt.Errorf("cannot open a session on the store %s: %w", database, err)
	}
	return &nssToken{context: context, handle: handle}, nil
}

// login logs the session in as the user with the empty PIN.
func (t *nssToken) login() error {
	err := t.context.Login(t.handle, pkcs11.CKU_USER, "")
	var code pkcs11.Error
	if errors.As(err, &code) && code == pkcs11.CKR_USER_ALREADY_LOGGED_IN {
		return nil
	}
	return err
}

// certificateSlot is the slot of the store's certificate token.
func certificateSlot(context *pkcs11.Ctx) (uint, error) {
	slots, err := context.GetSlotList(true)
	if err != nil {
		return 0, err
	}
	for _, slot := range slots {
		info, err := context.GetTokenInfo(slot)
		if err == nil && strings.TrimSpace(info.Label) == nssCertificateToken {
			return slot, nil
		}
	}
	return 0, errors.New("no certificate token in it")
}

// release finalises the library this process initialised for a store.
func release(context *pkcs11.Ctx) {
	_ = context.Finalize()
	context.Destroy()
}

// close ends the session and releases the store.
func (t *nssToken) close() {
	_ = t.context.CloseSession(t.handle)
	release(t.context)
}

// find lists the objects matching a template.
func (t *nssToken) find(template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := t.context.FindObjectsInit(t.handle, template); err != nil {
		return nil, err
	}
	var found []pkcs11.ObjectHandle
	for {
		objects, _, err := t.context.FindObjects(t.handle, 16)
		if err != nil {
			_ = t.context.FindObjectsFinal(t.handle)
			return nil, err
		}
		if len(objects) == 0 {
			break
		}
		found = append(found, objects...)
	}
	if err := t.context.FindObjectsFinal(t.handle); err != nil {
		return nil, err
	}
	return found, nil
}

// rootTemplate matches the objects of one class that carry the root's nickname.
func rootTemplate(class uint, extra ...*pkcs11.Attribute) []*pkcs11.Attribute {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, Nickname),
	}
	return append(template, extra...)
}

// rootCertificate is a certificate of the root in a store, with what its trust
// object is found by.
type rootCertificate struct {
	handle pkcs11.ObjectHandle
	issuer []byte
	serial []byte
}

// attribute reads one attribute of an object.
func (t *nssToken) attribute(object pkcs11.ObjectHandle, kind uint) ([]byte, error) {
	values, err := t.context.GetAttributeValue(t.handle, object, []*pkcs11.Attribute{pkcs11.NewAttribute(kind, nil)})
	if err != nil {
		return nil, err
	}
	return values[0].Value, nil
}

// rootCertificates finds the root's certificates in a store, by nickname.
func (t *nssToken) rootCertificates() ([]rootCertificate, error) {
	handles, err := t.find(rootTemplate(pkcs11.CKO_CERTIFICATE))
	if err != nil {
		return nil, err
	}
	var found []rootCertificate
	for _, handle := range handles {
		issuer, err := t.attribute(handle, pkcs11.CKA_ISSUER)
		if err != nil {
			return nil, err
		}
		serial, err := t.attribute(handle, pkcs11.CKA_SERIAL_NUMBER)
		if err != nil {
			return nil, err
		}
		found = append(found, rootCertificate{handle: handle, issuer: issuer, serial: serial})
	}
	return found, nil
}

// trustOf finds the trust objects of a certificate. NSS keeps a trust object by
// its issuer and serial, and certutil's carry no nickname, so they are found
// that way; extra narrows the search.
func (t *nssToken) trustOf(certificate rootCertificate, extra ...*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ckoNSSTrust),
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, certificate.issuer),
		pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, certificate.serial),
	}
	return t.find(append(template, extra...))
}

// dropRoot destroys the root's certificates and their trust objects, if the
// store holds them.
func (t *nssToken) dropRoot() error {
	certificates, err := t.rootCertificates()
	if err != nil {
		return err
	}
	for _, certificate := range certificates {
		trusts, err := t.trustOf(certificate)
		if err != nil {
			return err
		}
		for _, object := range append(trusts, certificate.handle) {
			if err := t.context.DestroyObject(t.handle, object); err != nil {
				return err
			}
		}
	}
	return nil
}

// hasRoot reports whether a store holds the root. NSS shows the trust of a root
// certutil installed only through its own library, not through PKCS#11, so a
// store is checked by its root certificate: the nickname is one only the install
// gives it, and the install writes the trust with the certificate.
func hasRoot(database string) (Presence, error) {
	token, err := openToken(database, false)
	if err != nil {
		return Absent, err
	}
	defer token.close()
	certificates, err := token.rootCertificates()
	if err != nil {
		return Absent, err
	}
	if len(certificates) == 0 {
		return Absent, nil
	}
	return Present, nil
}

// writeRoot puts the root in a store as an authority for servers, replacing
// one an earlier install left.
func writeRoot(database string, root *x509.Certificate) error {
	token, err := openToken(database, true)
	if err != nil {
		return err
	}
	defer token.close()
	if err := token.dropRoot(); err != nil {
		return err
	}
	serial, err := asn1.Marshal(root.SerialNumber)
	if err != nil {
		return err
	}
	certificate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, Nickname),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, root.Raw),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, root.RawSubject),
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, root.RawIssuer),
		pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, serial),
	}
	if _, err := token.context.CreateObject(token.handle, certificate); err != nil {
		return fmt.Errorf("the certificate: %w", err)
	}
	sha1Digest := sha1.Sum(root.Raw)
	md5Digest := md5.Sum(root.Raw)
	trust := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ckoNSSTrust),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, Nickname),
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, root.RawIssuer),
		pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, serial),
		pkcs11.NewAttribute(ckaCertSHA1Hash, sha1Digest[:]),
		pkcs11.NewAttribute(ckaCertMD5Hash, md5Digest[:]),
		pkcs11.NewAttribute(ckaTrustServerAuth, cktNSSTrustedDelegator),
		pkcs11.NewAttribute(ckaTrustEmailProtection, cktNSSTrustUnknown),
		pkcs11.NewAttribute(ckaTrustCodeSigning, cktNSSTrustUnknown),
	}
	if _, err := token.context.CreateObject(token.handle, trust); err != nil {
		return fmt.Errorf("the trust: %w", err)
	}
	return nil
}

// removeRoot takes the root out of a store.
func removeRoot(database string) error {
	token, err := openToken(database, true)
	if err != nil {
		return err
	}
	defer token.close()
	return token.dropRoot()
}

// makeStore creates the store's databases, or opens the ones there. A store
// with no password record yet gets the empty one, as certutil -N
// --empty-password sets it; a store that has one is left as it is.
func makeStore(directory string) error {
	token, err := openSession(directory, true)
	if err != nil {
		return err
	}
	defer token.close()
	if err := token.login(); err == nil {
		return nil
	}
	if err := token.context.Login(token.handle, pkcs11.CKU_SO, ""); err != nil {
		return fmt.Errorf("cannot set the empty password of the store %s: %w", directory, err)
	}
	if err := token.context.InitPIN(token.handle, ""); err != nil {
		return fmt.Errorf("cannot set the empty password of the store %s: %w", directory, err)
	}
	return token.context.Logout(token.handle)
}
