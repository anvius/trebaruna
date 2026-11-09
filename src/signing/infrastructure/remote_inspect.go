package infrastructure

import (
	"context"
	"crypto/x509"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/csc"
	transparencydomain "codeberg.org/simplicer/trebaruna/src/transparency/domain"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
)

// RemoteInspector lists the credentials a CSC service holds for the
// account as a token listing: a slot per credential, named by it, whose
// certificate is the credential's and whose PIN state says whether a
// signature asks for a PIN. The window chooses among them as among a
// card's certificates.
type RemoteInspector struct {
	Service domain.RemoteService
}

// Inspect signs in, lists the credentials and reads each.
func (i RemoteInspector) Inspect() ([]TokenSlot, error) {
	client := csc.NewClient(i.Service.Address, transparency.Client(transparencydomain.PurposeRemoteSigning, remoteTimeout))
	ctx, cancel := context.WithTimeout(context.Background(), remoteTimeout)
	defer cancel()
	if _, err := signIn(ctx, client, i.Service); err != nil {
		return nil, err
	}
	identifiers := []string{i.Service.Credential}
	if i.Service.Credential == "" {
		var err error
		if identifiers, err = client.Credentials(ctx); err != nil {
			return nil, err
		}
	}

	host := i.Service.Host()
	slots := make([]TokenSlot, 0, len(identifiers))
	for index, identifier := range identifiers {
		credential, err := client.Credential(ctx, identifier)
		if err != nil {
			return nil, err
		}
		slot := TokenSlot{Index: index, Description: identifier, TokenLabel: host, LoginState: "remote",
			PINState: domain.PINNotRequired}
		if credential.NeedsPIN {
			slot.PINState = domain.PINReady
		}
		if len(credential.Certificates) > 0 {
			if certificate, err := x509.ParseCertificate(credential.Certificates[0]); err == nil {
				described := describeCertificate(certificate)
				described.Credential = identifier
				described.SignsByDefault = len(identifiers) == 1
				slot.Certificates = []TokenCertificate{described}
			}
		}
		slots = append(slots, slot)
	}
	return slots, nil
}
