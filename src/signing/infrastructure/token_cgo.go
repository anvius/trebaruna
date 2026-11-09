//go:build cgo

package infrastructure

import (
	"crypto"
	"errors"
	"fmt"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"github.com/eclipse-keypont/crypto11"
)

// pkcs11Context adapts crypto11.Context to our tokenContext port.
type pkcs11Context struct {
	inner *crypto11.Context
}

// Pairs maps the library's tls.Certificate list onto our neutral type.
func (p pkcs11Context) Pairs() ([]tokenPair, error) {
	certificates, err := p.inner.FindAllPairedCertificates()
	if err != nil {
		return nil, err
	}

	pairs := make([]tokenPair, 0, len(certificates))
	for _, certificate := range certificates {
		signer, ok := certificate.PrivateKey.(crypto.Signer)
		if !ok {
			continue
		}
		if len(certificate.Certificate) == 0 {
			continue
		}
		pairs = append(pairs, tokenPair{
			Certificate: certificate.Certificate[0],
			Chain:       certificate.Certificate[1:],
			Signer:      signer,
		})
	}
	return pairs, nil
}

// Close releases the PKCS#11 session.
func (p pkcs11Context) Close() error { return p.inner.Close() }

// openToken connects to the smartcard through crypto11.
//
// Guarded by the cgo build tag: the static binary (P12/PEM only) omits it.
func openToken(signer domain.Signer) (tokenContext, error) {
	config := &crypto11.Config{
		Path:       signer.PKCS11Module(),
		TokenLabel: signer.PKCS11Token(),
		Pin:        signer.PKCS11PIN(),
	}
	if signer.PKCS11Token() == "" {
		slot, err := slotHolding(signer)
		if err != nil {
			return nil, err
		}
		config.SlotNumber = &slot
	}
	context, err := crypto11.Configure(config)
	if err != nil {
		return nil, fmt.Errorf(
			"cannot open %s with module %s: %w\n"+
				"  check: systemctl status pcscd ; pcsc_scan ; pkcs11-tool -L",
			tokenName(signer), signer.PKCS11Module(), err,
		)
	}
	return pkcs11Context{inner: context}, nil
}

// slotHolding finds the reader whose card holds the certificate to sign with,
// for a signer that named no token.
//
// The cards are read without a PIN: trying the PIN on every card in every
// reader would spend the attempts of cards that are not the one meant. A card
// that shows no certificate before login is still found when it is the only
// card present.
func slotHolding(signer domain.Signer) (int, error) {
	slots, err := inspectToken(signer.PKCS11Module(), "")
	if err != nil {
		return 0, err
	}

	choice := signer.CertificateChoice()
	var holding, present []TokenSlot
	for _, slot := range slots {
		if slot.TokenLabel == "" {
			continue
		}
		present = append(present, slot)
		if _, err := choice.Pick(parsedCertificates(slot.Certificates)); !errors.Is(err, domain.ErrNoCertificateMatches) {
			holding = append(holding, slot)
		}
	}
	if len(holding) == 0 && choice.Automatic() && len(present) == 1 {
		holding = present
	}

	switch len(holding) {
	case 1:
		return holding[0].Index, nil
	case 0:
		if choice.Automatic() {
			return 0, fmt.Errorf("no card in the readers of %s shows a certificate.\n"+
				"  check: the card is inserted and pcscd is running; list them with: trebaruna token",
				signer.PKCS11Module())
		}
		return 0, fmt.Errorf("%w %q in any reader of %s; list them with: trebaruna token",
			domain.ErrNoCertificateMatches, choice.String(), signer.PKCS11Module())
	default:
		labels := make([]string, len(holding))
		for index, slot := range holding {
			labels[index] = fmt.Sprintf("%q", slot.TokenLabel)
		}
		return 0, fmt.Errorf("several cards can sign (%s): name the token to use",
			strings.Join(labels, ", "))
	}
}

// PKCS11Available reports that this build can talk to smartcards and tokens.
const PKCS11Available = true
