package cli

import "flag"

// keyFlags are the flags that say where a private key is: a file, a card or a
// software store. `sign` and `decrypt` share them.
type keyFlags struct {
	p12, pem, passphrase, pin, token, certificate, module, nssDB *string
	card, firefox                                                *bool
	remote, credential, oauthClient, oauthRedirect               *string
}

// addKeyFlags registers the key flags; purpose completes "the certificate
// to …" in their descriptions.
func addKeyFlags(flags *flag.FlagSet, purpose string) keyFlags {
	return keyFlags{
		p12:        flags.String("p12", "", "PKCS#12 file with the certificate to "+purpose),
		pem:        flags.String("pem", "", "PEM bundle with certificate and private key"),
		passphrase: flags.String("pass", "", "passphrase for the P12 or PEM file (or $TREBARUNA_PASSPHRASE)"),
		pin:        flags.String("pin", "", "PIN for PKCS#11 tokens (or $TREBARUNA_PIN)"),
		token:      flags.String("token", "", "PKCS#11 token label (smartcard)"),
		card:       flags.Bool("card", false, "use the card in the reader (OpenSC; the card and its certificate are found)"),
		certificate: flags.String("certificate", "",
			"certificate of the card to "+purpose+": serial or SHA-256 fingerprint (see `trebaruna token`)"),
		module:  flags.String("module", "", "PKCS#11 module path (default: OpenSC, found on this system)"),
		firefox: flags.Bool("firefox", false, "use a certificate of the Firefox store, in place (PIN: its primary password)"),
		nssDB:   flags.String("nss-db", "", "use a certificate of this NSS store directory (Chromium: ~/.pki/nssdb)"),
		remote: flags.String("csc", "", "sign with a key kept by a provider, through its Cloud Signature Consortium API (https://…/csc/v2); "+
			"secrets in $TREBARUNA_CSC_TOKEN or $TREBARUNA_CSC_USER/_PASSWORD, $TREBARUNA_PIN, $TREBARUNA_OTP"),
		credential: flags.String("credential", "", "the provider's credential to sign with (default: its only one)"),
		oauthClient: flags.String("csc-client", "", "the client id the provider gave trebaruna, to sign in or authorise a signature "+
			"in your browser through its OAuth2 server (client secret, if any, in $TREBARUNA_CSC_CLIENT_SECRET)"),
		oauthRedirect: flags.String("csc-redirect", "", "the address your browser comes back to after authorising, "+
			"as registered with the provider (default: http://127.0.0.1:<free port>/callback)"),
	}
}

// options turns the parsed flags into the signer options.
func (k keyFlags) options(name string) signerOptions {
	return signerOptions{
		name: name, p12Path: *k.p12, pemPath: *k.pem, passphrase: *k.passphrase,
		pin: *k.pin, card: *k.card, tokenLabel: *k.token, certificate: *k.certificate, module: *k.module,
		store:  storeOptions{firefox: *k.firefox, directory: *k.nssDB},
		remote: *k.remote, credential: *k.credential, oauthClient: *k.oauthClient, oauthRedirect: *k.oauthRedirect,
	}
}

// keyValueFlagNames are the key flags that take a value.
var keyValueFlagNames = []string{"p12", "pem", "pass", "pin", "token", "module", "certificate", "nss-db", "csc", "credential",
	"csc-client", "csc-redirect"}

// valueFlagsWith returns the key flags that take a value plus the named ones,
// in both their - and -- forms, for telling flag values from documents.
func valueFlagsWith(names ...string) map[string]bool {
	flags := map[string]bool{}
	for _, name := range append(append([]string{}, keyValueFlagNames...), names...) {
		flags["-"+name], flags["--"+name] = true, true
	}
	return flags
}
