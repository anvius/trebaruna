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
	"sync"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/domain/identity"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/csc"
	transparencydomain "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
)

// remoteTimeout bounds each call to the remote service; authorising in the
// browser, which waits for a person, gets longer.
const (
	remoteTimeout = time.Minute
	oauthTimeout  = 5 * time.Minute
)

// loadRemote is the CSC credential of the signer's service, as a key pair.
func loadRemote(signer domain.Signer) (KeyPair, error) {
	credential, err := rememberedCredentials.load(signer.Remote())
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		Signer:      credential.key,
		Certificate: credential.certificate,
		Chain:       credential.chain,
		Name:        signer.NameFor(identity.FromCertificate(credential.certificate).Name),
		SelfSigned:  isSelfSigned(credential.certificate),
		KeySource:   domain.FromRemote,
	}, nil
}

// remoteCredential is a credential read from its service: the key that
// signs through it and its certificates.
type remoteCredential struct {
	key         remoteKey
	certificate *x509.Certificate
	chain       []*x509.Certificate
}

// credentialMemory keeps a credential read for as long as one call to the
// service may last: signing a document reads the signer's identity and then
// signs, and each loads the key, but the provider is asked once.
type credentialMemory struct {
	mutex       sync.Mutex
	credentials map[domain.RemoteService]rememberedCredential
}

type rememberedCredential struct {
	credential remoteCredential
	until      time.Time
}

var rememberedCredentials = &credentialMemory{credentials: map[domain.RemoteService]rememberedCredential{}}

// load is the service's credential, read again once its moment is past.
func (m *credentialMemory) load(service domain.RemoteService) (remoteCredential, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	now := time.Now()
	for known, remembered := range m.credentials {
		if now.After(remembered.until) {
			delete(m.credentials, known)
		}
	}
	if remembered, ok := m.credentials[service]; ok {
		return remembered.credential, nil
	}
	credential, err := readCredential(service)
	if err != nil {
		return remoteCredential{}, err
	}
	m.credentials[service] = rememberedCredential{credential: credential, until: now.Add(remoteTimeout)}
	return credential, nil
}

// readCredential reaches a CSC credential (ADR-0014): sign in, find the one
// credential or the one named, read its certificates, and check it can sign
// before any document is touched.
func readCredential(service domain.RemoteService) (remoteCredential, error) {
	client := csc.NewClient(service.Address, transparency.Client(transparencydomain.PurposeRemoteSigning, remoteTimeout))
	ctx, cancel := context.WithTimeout(context.Background(), remoteTimeout)
	defer cancel()

	var oauth *csc.OAuth
	switch {
	case service.Token != "":
		client.UseToken(service.Token)
	case service.User != "":
		if err := client.Login(ctx, service.User, service.Password); err != nil {
			return remoteCredential{}, err
		}
	case service.OAuthClient != "":
		var err error
		if oauth, err = oauthOf(ctx, client, service); err != nil {
			return remoteCredential{}, err
		}
		signIn, cancelSignIn := context.WithTimeout(context.Background(), oauthTimeout)
		token, err := oauth.ServiceToken(signIn)
		cancelSignIn()
		if err != nil {
			return remoteCredential{}, err
		}
		client.UseToken(token)
	default:
		return remoteCredential{}, errors.New("a remote signing service needs $TREBARUNA_CSC_TOKEN, $TREBARUNA_CSC_USER and " +
			"$TREBARUNA_CSC_PASSWORD, or --csc-client to sign in through the provider's OAuth2 server")
	}

	credentialID, err := chooseCredential(ctx, client, service.Credential)
	if err != nil {
		return remoteCredential{}, err
	}
	credential, err := client.Credential(ctx, credentialID)
	if err != nil {
		return remoteCredential{}, err
	}
	switch {
	case !credential.KeyEnabled:
		return remoteCredential{}, fmt.Errorf("the key of credential %s is not enabled", credentialID)
	case !credential.CertValid:
		return remoteCredential{}, fmt.Errorf("the certificate of credential %s is not valid", credentialID)
	case len(credential.Certificates) == 0:
		return remoteCredential{}, fmt.Errorf("credential %s carries no certificate", credentialID)
	case credential.Explicit && credential.NeedsPIN && service.PIN == "":
		return remoteCredential{}, fmt.Errorf("credential %s asks for a PIN for each signature: set $TREBARUNA_PIN", credentialID)
	case credential.Explicit && credential.NeedsOTP && service.OTP == "":
		return remoteCredential{}, fmt.Errorf("credential %s asks for a one-time password: set $TREBARUNA_OTP", credentialID)
	case credential.OAuth && service.OAuthClient == "":
		return remoteCredential{}, fmt.Errorf("credential %s is authorised in the browser, through the provider's OAuth2 server: "+
			"give the client id the provider gave trebaruna with --csc-client", credentialID)
	}
	if credential.OAuth && oauth == nil {
		if oauth, err = oauthOf(ctx, client, service); err != nil {
			return remoteCredential{}, err
		}
	}

	certificate, err := x509.ParseCertificate(credential.Certificates[0])
	if err != nil {
		return remoteCredential{}, fmt.Errorf("the certificate of credential %s: %w", credentialID, err)
	}
	var chain []*x509.Certificate
	for _, der := range credential.Certificates[1:] {
		if issuer, err := x509.ParseCertificate(der); err == nil {
			chain = append(chain, issuer)
		}
	}
	key := remoteKey{client: client, credential: credentialID, public: certificate.PublicKey,
		algorithms: credential.KeyAlgorithms, explicit: credential.Explicit, pin: service.PIN, otp: service.OTP}
	if credential.OAuth {
		key.oauth = oauth
	}
	return remoteCredential{key: key, certificate: certificate, chain: chain}, nil
}

// oauthOf is the service's OAuth2 server, as info names it, for the client
// the person gave.
func oauthOf(ctx context.Context, client *csc.Client, service domain.RemoteService) (*csc.OAuth, error) {
	described, err := client.Info(ctx)
	if err != nil {
		return nil, err
	}
	if described.OAuth2 == "" {
		return nil, fmt.Errorf("the service names no OAuth2 server (info's oauth2)")
	}
	return &csc.OAuth{
		Base: described.OAuth2, ClientID: service.OAuthClient, ClientSecret: service.OAuthSecret, Redirect: service.OAuthRedirect,
		HTTP: transparency.Client(transparencydomain.PurposeRemoteSigning, remoteTimeout), Open: openInBrowser,
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
	// oauth authorises each signature in the person's browser.
	oauth *csc.OAuth
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
	if k.oauth != nil {
		return k.signAuthorisedInBrowser(digest, hashOID, signatureOID)
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
	return k.fromService(signatures[0])
}

// signAuthorisedInBrowser has the person authorise this one digest in their
// browser; the credential-scoped token the provider then gives stands in
// for the activation data.
func (k remoteKey) signAuthorisedInBrowser(digest []byte, hashOID, signatureOID string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), oauthTimeout)
	defer cancel()
	token, err := k.oauth.CredentialToken(ctx, k.credential, [][]byte{digest}, hashOID)
	if err != nil {
		return nil, err
	}
	signatures, err := k.client.WithToken(token).SignHash(ctx, k.credential, "", [][]byte{digest}, hashOID, signatureOID)
	if err != nil {
		return nil, err
	}
	return k.fromService(signatures[0])
}

// fromService is a signature as crypto.Signer promises it.
func (k remoteKey) fromService(signature []byte) ([]byte, error) {
	if public, ok := k.public.(*ecdsa.PublicKey); ok {
		return remoteECDSA(public, signature)
	}
	return signature, nil
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
