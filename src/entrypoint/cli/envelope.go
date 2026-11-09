package cli

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"codeberg.org/simplicer/trebaruna/src/encryption/application"
	"codeberg.org/simplicer/trebaruna/src/encryption/infrastructure"
)

// recipientList is the repeatable --to flag.
type recipientList []string

func (r *recipientList) String() string         { return fmt.Sprint(*r) }
func (r *recipientList) Set(value string) error { *r = append(*r, value); return nil }

// runEncrypt implements `trebaruna encrypt`: a .p7e only the recipients'
// certificates open.
func runEncrypt(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var recipients recipientList
	flags.Var(&recipients, "to", "certificate (.pem/.cer/.crt) of a recipient; repeat for each")
	var (
		oaep   = flags.Bool("oaep", false, "send the key with RSA-OAEP (default PKCS#1 v1.5, which every tool reads)")
		output = flags.String("out", "", "output path (default: <document>.p7e)")
		asJSON = flags.Bool("json", false, "machine-readable output")
	)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: trebaruna encrypt <document> --to <certificate> [--to …] [--oaep] [--out path]")
		flags.PrintDefaults()
	}
	flagArguments, positional := splitArguments(args, map[string]bool{"-to": true, "--to": true, "-out": true, "--out": true})
	if err := flags.Parse(flagArguments); err != nil {
		return exitUsage
	}
	if len(positional) != 1 {
		flags.Usage()
		return exitUsage
	}

	certificates := make([]*x509.Certificate, 0, len(recipients))
	for _, path := range recipients {
		certificate, err := readCertificateFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitUsage
		}
		certificates = append(certificates, certificate)
	}

	envelope, err := application.NewEncryptDocument(infrastructure.LocalFiles{}, infrastructure.CMSSealer{}, time.Now).
		Execute(context.Background(), application.EncryptRequest{
			Document: positional[0], Recipients: certificates, OAEP: *oaep, Output: *output,
		})
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}
	if *asJSON {
		encodeJSONValue(stdout, map[string]any{"path": envelope.Path, "size": envelope.Size, "recipients": envelope.Recipients})
		return exitOK
	}
	fmt.Fprintf(stdout, "encrypted  %s\n", envelope.Path)
	for _, name := range envelope.Recipients {
		fmt.Fprintf(stdout, "  opens with the key of %s\n", name)
	}
	return exitOK
}

// runDecrypt implements `trebaruna decrypt`: the document of a .p7e, with the
// key of a file, a card or a store.
func runDecrypt(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	flags.SetOutput(stderr)
	keys := addKeyFlags(flags, "decrypt with")
	var (
		output = flags.String("out", "", "output path (default: the envelope without .p7e)")
		asJSON = flags.Bool("json", false, "machine-readable output")
	)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: trebaruna decrypt <envelope.p7e> (--p12 key.p12 | --card | --firefox …) [--out path]")
		flags.PrintDefaults()
	}
	flagArguments, positional := splitArguments(args, valueFlagsWith("out"))
	if err := flags.Parse(flagArguments); err != nil {
		return exitUsage
	}
	if len(positional) != 1 {
		flags.Usage()
		return exitUsage
	}
	key, err := buildSigner(keys.options(""))
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	decrypted, err := application.NewDecryptDocument(infrastructure.LocalFiles{}, infrastructure.KeyOpener{}).
		Execute(context.Background(), application.DecryptRequest{Envelope: positional[0], Key: key, Output: *output})
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitInvalid
	}
	if *asJSON {
		encodeJSONValue(stdout, map[string]any{"path": decrypted.Path, "size": decrypted.Size})
		return exitOK
	}
	fmt.Fprintf(stdout, "decrypted  %s (%d bytes)\n", decrypted.Path, decrypted.Size)
	return exitOK
}

// readCertificateFile reads a certificate in PEM or DER.
func readCertificateFile(path string) (*x509.Certificate, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(content); block != nil {
		content = block.Bytes
	}
	certificate, err := x509.ParseCertificate(content)
	if err != nil {
		return nil, fmt.Errorf("%s is not a certificate: %w", path, err)
	}
	return certificate, nil
}
