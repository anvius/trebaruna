//go:build cgo

package infrastructure

// #include <stdlib.h>
import "C"

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"unsafe"

	"github.com/miekg/pkcs11"
)

// The PKCS#11 session the signatures go through, written over the plain
// binding instead of a wrapper library: it is a few hundred lines, it reads
// in one sitting, and it can pass what the wrappers cannot — the
// initialisation parameters NSS needs to open a Firefox profile, and an
// absent PIN to a reader with its own keypad.

// module is a loaded and initialised PKCS#11 library.
type module struct {
	context *pkcs11.Ctx
	// finalize says whether this process initialised the library, and so
	// must finalise it: a library someone else initialised stays up.
	finalize bool
}

// loadModule loads the library and initialises it, with the parameters some
// modules take in the reserved field of C_Initialize (NSS's configdir).
func loadModule(path, parameters string) (module, error) {
	if path == "" {
		return module{}, fmt.Errorf("no PKCS#11 module given: use --module <path>")
	}
	context := pkcs11.New(path)
	if context == nil {
		return module{}, fmt.Errorf("cannot load the PKCS#11 module %s", path)
	}

	var options []pkcs11.InitializeOption
	if parameters != "" {
		// NSS reads its LibraryParameters string from this field and copies it
		// during the call, so the memory is released right after.
		reserved := C.CString(parameters)
		defer C.free(unsafe.Pointer(reserved))
		options = append(options, pkcs11.InitializeWithReserved(unsafe.Pointer(reserved)))
	}

	loaded := module{context: context, finalize: true}
	if err := context.Initialize(options...); err != nil {
		if !alreadyInitialised(err) {
			context.Destroy()
			return module{}, fmt.Errorf(
				"cannot initialise the PKCS#11 module %s: %w\n"+
					"  check: the path exists, the reader is connected, and pcscd is running",
				path, err)
		}
		// Finalising a library another caller initialised would take it down
		// for them.
		loaded.finalize = false
	}
	return loaded, nil
}

// unload finalises the library if this process initialised it.
func (m module) unload() {
	if m.finalize {
		_ = m.context.Finalize()
	}
	m.context.Destroy()
}

// alreadyInitialised reports CKR_CRYPTOKI_ALREADY_INITIALIZED.
func alreadyInitialised(err error) bool {
	var code pkcs11.Error
	return errors.As(err, &code) && code == pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED
}

// cardSessions lets one card session exist at a time in this process. A
// PKCS#11 login belongs to the whole application, not to one session: while a
// session was logged in, a second login answered "already logged in" and a
// wrong PIN would have signed. One session at a time keeps every PIN checked.
var cardSessions sync.Mutex

// session is one logged-in session on one slot. Every signature goes through
// it, one at a time.
type session struct {
	module module
	handle pkcs11.SessionHandle
	mutex  sync.Mutex
	closed bool
}

// openSession opens a session on the slot and, when asked, logs in as the
// user (CKU_USER, with the PIN) or the security officer (CKU_SO, with the
// PUK).
func openSession(path, parameters string, slot uint, userType uint, secret string, login bool) (*session, error) {
	cardSessions.Lock()
	loaded, err := loadModule(path, parameters)
	if err != nil {
		cardSessions.Unlock()
		return nil, err
	}
	handle, err := loaded.context.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		// A read-only session signs as well; some stores open read-only.
		handle, err = loaded.context.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	}
	if err != nil {
		loaded.unload()
		cardSessions.Unlock()
		return nil, err
	}

	opened := &session{module: loaded, handle: handle}
	if login {
		// An empty PIN with a zero length is how a reader with a keypad is
		// asked to read the PIN itself (OpenSC treats it so); elsewhere the
		// caller never gets here without a PIN.
		err := loaded.context.Login(handle, userType, secret)
		var code pkcs11.Error
		if errors.As(err, &code) && code == pkcs11.CKR_USER_ALREADY_LOGGED_IN {
			// A login left over from elsewhere in this process must not stand
			// in for this PIN: log out and let the card check it.
			_ = loaded.context.Logout(handle)
			err = loaded.context.Login(handle, userType, secret)
		}
		if err != nil {
			_ = opened.Close()
			return nil, err
		}
	}
	return opened, nil
}

// Close logs out, closes the session and releases the library.
func (s *session) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	_ = s.module.context.Logout(s.handle)
	_ = s.module.context.CloseSession(s.handle)
	s.module.unload()
	cardSessions.Unlock()
	return nil
}

// Pairs lists every private key with the certificate that shares its CKA_ID,
// and the issuers of that certificate the token also holds.
func (s *session) Pairs() ([]tokenPair, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	keys, err := s.find(pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return nil, err
	}
	handles, err := s.find(pkcs11.CKO_CERTIFICATE)
	if err != nil {
		return nil, err
	}

	var identifiers [][]byte
	var held []*x509.Certificate
	for _, handle := range handles {
		values, err := s.attributes(handle, pkcs11.CKA_ID, pkcs11.CKA_VALUE)
		if err != nil {
			continue
		}
		parsed, err := x509.ParseCertificate(values[1])
		if err != nil {
			continue
		}
		identifiers = append(identifiers, values[0])
		held = append(held, parsed)
	}

	var pairs []tokenPair
	for _, key := range keys {
		values, err := s.attributes(key, pkcs11.CKA_ID)
		if err != nil || len(values[0]) == 0 {
			continue
		}
		for index, identifier := range identifiers {
			if !bytes.Equal(identifier, values[0]) {
				continue
			}
			leaf := held[index]
			var chain [][]byte
			for _, issuer := range issuersOf(leaf, held) {
				chain = append(chain, issuer.Raw)
			}
			pairs = append(pairs, tokenPair{
				Certificate: leaf.Raw,
				Chain:       chain,
				Signer:      tokenKey{session: s, handle: key, public: leaf.PublicKey},
			})
			break
		}
	}
	return pairs, nil
}

// issuersOf walks up from the leaf through the certificates the token holds,
// stopping at a self-signed one or after a few steps.
func issuersOf(leaf *x509.Certificate, held []*x509.Certificate) []*x509.Certificate {
	var chain []*x509.Certificate
	current := leaf
	for range 6 {
		if bytes.Equal(current.RawIssuer, current.RawSubject) {
			break
		}
		var next *x509.Certificate
		for _, candidate := range held {
			if bytes.Equal(candidate.RawSubject, current.RawIssuer) && !candidate.Equal(current) &&
				current.CheckSignatureFrom(candidate) == nil {
				next = candidate
				break
			}
		}
		if next == nil {
			break
		}
		chain = append(chain, next)
		current = next
	}
	return chain
}

// find lists the objects of a class.
func (s *session) find(class uint) ([]pkcs11.ObjectHandle, error) {
	context := s.module.context
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, class)}
	if err := context.FindObjectsInit(s.handle, template); err != nil {
		return nil, err
	}
	defer context.FindObjectsFinal(s.handle)

	var found []pkcs11.ObjectHandle
	for {
		batch, _, err := context.FindObjects(s.handle, 32)
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			return found, nil
		}
		found = append(found, batch...)
	}
}

// attributes reads the values of an object's attributes, in order.
func (s *session) attributes(handle pkcs11.ObjectHandle, types ...uint) ([][]byte, error) {
	template := make([]*pkcs11.Attribute, len(types))
	for index, kind := range types {
		template[index] = pkcs11.NewAttribute(kind, nil)
	}
	read, err := s.module.context.GetAttributeValue(s.handle, handle, template)
	if err != nil {
		return nil, err
	}
	values := make([][]byte, len(types))
	for _, attribute := range read {
		for index, kind := range types {
			if attribute.Type == kind {
				values[index] = attribute.Value
			}
		}
	}
	return values, nil
}

// tokenKey is a private key that never leaves the token: Sign asks the token
// to sign.
type tokenKey struct {
	session *session
	handle  pkcs11.ObjectHandle
	public  crypto.PublicKey
}

// Public returns the public key of the certificate paired with the key.
func (k tokenKey) Public() crypto.PublicKey { return k.public }

// Sign signs a digest: PKCS#1 v1.5 or PSS for RSA, and ECDSA with the token's
// r||s answer re-encoded as the ASN.1 sequence Go and CMS expect.
func (k tokenKey) Sign(_ io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	var mechanism *pkcs11.Mechanism
	input := digest

	switch k.public.(type) {
	case *rsa.PublicKey:
		if pss, ok := options.(*rsa.PSSOptions); ok {
			parameters, err := pssParameters(pss, len(digest))
			if err != nil {
				return nil, err
			}
			mechanism = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, parameters)
			break
		}
		prefix, known := digestInfoPrefixes[options.HashFunc()]
		if !known {
			return nil, fmt.Errorf("the token cannot sign a %v digest with PKCS#1 v1.5", options.HashFunc())
		}
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
		input = append(append([]byte{}, prefix...), digest...)
	case *ecdsa.PublicKey:
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	default:
		return nil, fmt.Errorf("the token's key type %T cannot sign", k.public)
	}

	k.session.mutex.Lock()
	defer k.session.mutex.Unlock()
	context := k.session.module.context
	if err := context.SignInit(k.session.handle, []*pkcs11.Mechanism{mechanism}, k.handle); err != nil {
		return nil, err
	}
	signature, err := context.Sign(k.session.handle, input)
	if err != nil {
		return nil, err
	}
	if _, isECDSA := k.public.(*ecdsa.PublicKey); isECDSA {
		return asn1ECDSA(signature)
	}
	return signature, nil
}

// asn1ECDSA turns the r||s a token returns into SEQUENCE { r, s }.
func asn1ECDSA(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw)%2 != 0 {
		return nil, fmt.Errorf("the token returned an ECDSA signature of %d bytes", len(raw))
	}
	half := len(raw) / 2
	return asn1.Marshal(struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes(raw[:half]),
		S: new(big.Int).SetBytes(raw[half:]),
	})
}

// pssParameters builds CK_RSA_PKCS_PSS_PARAMS for the hash of the digest.
func pssParameters(options *rsa.PSSOptions, digestLength int) ([]byte, error) {
	mechanisms := map[crypto.Hash][2]uint{
		crypto.SHA256: {pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256},
		crypto.SHA384: {pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384},
		crypto.SHA512: {pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512},
	}
	pair, known := mechanisms[options.Hash]
	if !known {
		return nil, fmt.Errorf("the token cannot sign a %v digest with PSS", options.Hash)
	}
	salt := options.SaltLength
	if salt <= 0 {
		// rsa.PSSSaltLengthAuto and EqualsHash both mean the digest length
		// for a signature that must verify everywhere.
		salt = digestLength
	}
	return pkcs11.NewPSSParams(pair[0], pair[1], uint(salt)), nil
}

// digestInfoPrefixes are the DER DigestInfo headers PKCS#1 v1.5 puts before
// the digest (RFC 8017, section 9.2, note 1).
var digestInfoPrefixes = map[crypto.Hash][]byte{
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}
