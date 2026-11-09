package infrastructure

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/domain/identity"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/csc"
	transparencydomain "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
)

// remoteTimeout bounds each call to the remote service.
const remoteTimeout = time.Minute

// loadRemote reaches a CSC credential (ADR-0014): sign in, find the one
// credential or the one named, read its certificates, and check it can sign
// before any document is touched.
func loadRemote(signer domain.Signer) (KeyPair, error) {
	service := signer.Remote()
	client := csc.NewClient(service.Address, transparency.Client(transparencydomain.PurposeRemoteSigning, remoteTimeout))
	ctx, cancel := context.WithTimeout(context.Background(), remoteTimeout)
	defer cancel()

	switch {
	case service.Token != "":
		client.UseToken(service.Token)
	case service.User != "":
		if err := client.Login(ctx, service.User, service.Password); err != nil {
			return KeyPair{}, err
		}
	default:
		return KeyPair{}, errors.New("a remote signing service needs $TREBARUNA_CSC_TOKEN, or $TREBARUNA_CSC_USER and $TREBARUNA_CSC_PASSWORD")
	}

	credentialID, err := chooseCredential(ctx, client, service.Credential)
	if err != nil {
		return KeyPair{}, err
	}
	credential, err := client.Credential(ctx, credentialID)
	if err != nil {
		return KeyPair{}, err
	}
	switch {
	case !credential.KeyEnabled:
		return KeyPair{}, fmt.Errorf("the key of credential %s is not enabled", credentialID)
	case !credential.CertValid:
		return KeyPair{}, fmt.Errorf("the certificate of credential %s is not valid", credentialID)
	case len(credential.Certificates) == 0:
		return KeyPair{}, fmt.Errorf("credential %s carries no certificate", credentialID)
	case credential.Explicit && credential.NeedsPIN && service.PIN == "":
		return KeyPair{}, fmt.Errorf("credential %s asks for a PIN for each signature: set $TREBARUNA_PIN", credentialID)
	case credential.Explicit && credential.NeedsOTP && service.OTP == "":
		return KeyPair{}, fmt.Errorf("credential %s asks for a one-time password: set $TREBARUNA_OTP", credentialID)
	}

	certificate, err := x509.ParseCertificate(credential.Certificates[0])
	if err != nil {
		return KeyPair{}, fmt.Errorf("the certificate of credential %s: %w", credentialID, err)
	}
	var chain []*x509.Certificate
	for _, der := range credential.Certificates[1:] {
		if issuer, err := x509.ParseCertificate(der); err == nil {
			chain = append(chain, issuer)
		}
	}
	key := remoteKey{client: client, credential: credentialID, public: certificate.PublicKey,
		algorithms: credential.KeyAlgorithms, explicit: credential.Explicit, pin: service.PIN, otp: service.OTP}
	return KeyPair{
		Signer:      key,
		Certificate: certificate,
		Chain:       chain,
		Name:        signer.NameFor(identity.FromCertificate(certificate).Name),
		SelfSigned:  isSelfSigned(certificate),
		KeySource:   domain.FromRemote,
	}, nil
}

// chooseCredential is the credential named, or the account's only one.
func chooseCredential(ctx context.Context, client *csc.Client, named string) (string, error) {
	if named != "" {
		return named, nil
	}
	credentials, err := client.Credentials(ctx)
	if err != nil {
		return "", err
	}
	if len(credentials) != 1 {
		return "", fmt.Errorf("the service holds %d credentials; name one with --credential: %s", len(credentials), strings.Join(credentials, ", "))
	}
	return credentials[0], nil
}

// remoteKey is a key a provider keeps: signing sends it the hash, with the
// authorisation the credential asks for, and receives the signature.
type remoteKey struct {
	client     *csc.Client
	credential string
	public     crypto.PublicKey
	algorithms []string
	explicit   bool
	pin, otp   string
}

// Public is the certificate's key.
func (k remoteKey) Public() crypto.PublicKey { return k.public }

// Sign has the provider sign the digest: authorised for that digest alone
// when the credential is explicit, then signed.
func (k remoteKey) Sign(_ io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	if _, pss := options.(*rsa.PSSOptions); pss {
		return nil, errors.New("RSA-PSS through a remote service is not supported")
	}
	hashOID, signatureOID, err := k.algorithmsFor(options.HashFunc())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), remoteTimeout)
	defer cancel()
	sad := ""
	if k.explicit {
		if sad, err = k.client.Authorize(ctx, k.credential, [][]byte{digest}, hashOID, k.pin, k.otp); err != nil {
			return nil, err
		}
	}
	signatures, err := k.client.SignHash(ctx, k.credential, sad, [][]byte{digest}, hashOID, signatureOID)
	if err != nil {
		return nil, err
	}
	if public, ok := k.public.(*ecdsa.PublicKey); ok {
		return remoteECDSA(public, signatures[0])
	}
	return signatures[0], nil
}

// Hash and signature algorithm OIDs.
var (
	hashOIDs = map[crypto.Hash]string{
		crypto.SHA1: "1.3.14.3.2.26", crypto.SHA256: "2.16.840.1.101.3.4.2.1",
		crypto.SHA384: "2.16.840.1.101.3.4.2.2", crypto.SHA512: "2.16.840.1.101.3.4.2.3",
	}
	rsaWith = map[crypto.Hash]string{
		crypto.SHA1: "1.2.840.113549.1.1.5", crypto.SHA256: "1.2.840.113549.1.1.11",
		crypto.SHA384: "1.2.840.113549.1.1.12", crypto.SHA512: "1.2.840.113549.1.1.13",
	}
	ecdsaWith = map[crypto.Hash]string{
		crypto.SHA1: "1.2.840.10045.4.1", crypto.SHA256: "1.2.840.10045.4.3.2",
		crypto.SHA384: "1.2.840.10045.4.3.3", crypto.SHA512: "1.2.840.10045.4.3.4",
	}
)

const (
	rsaEncryption = "1.2.840.113549.1.1.1"
	ecPublicKey   = "1.2.840.10045.2.1"
)

// algorithmsFor names the hash and the signature algorithm: the combined
// OID (sha256WithRSAEncryption…) unless the credential lists only the key's
// own algorithm, which the provider then pairs with the hash.
func (k remoteKey) algorithmsFor(hash crypto.Hash) (string, string, error) {
	hashOID, known := hashOIDs[hash]
	if !known {
		return "", "", fmt.Errorf("hash %v is not offered to a remote service", hash)
	}
	var combined, plain string
	switch k.public.(type) {
	case *rsa.PublicKey:
		combined, plain = rsaWith[hash], rsaEncryption
	case *ecdsa.PublicKey:
		combined, plain = ecdsaWith[hash], ecPublicKey
	default:
		return "", "", fmt.Errorf("a %T key is not signed through a remote service", k.public)
	}
	if len(k.algorithms) > 0 && !slices.Contains(k.algorithms, combined) && slices.Contains(k.algorithms, plain) {
		return hashOID, plain, nil
	}
	return hashOID, combined, nil
}

// remoteECDSA returns an ECDSA signature in the ASN.1 form crypto.Signer
// promises, converting the r||s some providers return.
func remoteECDSA(public *ecdsa.PublicKey, signature []byte) ([]byte, error) {
	var parsed struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(signature, &parsed); err == nil && len(rest) == 0 {
		return signature, nil
	}
	size := (public.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*size {
		return nil, fmt.Errorf("the remote service returned an ECDSA signature of %d bytes", len(signature))
	}
	return asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(signature[:size]), new(big.Int).SetBytes(signature[size:]),
	})
}
