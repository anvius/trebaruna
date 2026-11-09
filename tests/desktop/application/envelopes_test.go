package application_test

import (
	"context"
	"errors"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

type scriptedEnvelopes struct {
	encrypted []domain.EncryptionIntent
	opened    []domain.OpeningIntent
	err       error
}

func (s *scriptedEnvelopes) Encrypt(_ context.Context, intent domain.EncryptionIntent) (domain.SealedEnvelope, error) {
	s.encrypted = append(s.encrypted, intent)
	return domain.SealedEnvelope{Path: intent.DocumentPath + ".p7e", Recipients: []string{"ANNA BIANCHI"}}, s.err
}

func (s *scriptedEnvelopes) Open(_ context.Context, intent domain.OpeningIntent) (domain.OpenedEnvelope, error) {
	s.opened = append(s.opened, intent)
	return domain.OpenedEnvelope{Path: "/tmp/offerta.pdf", Size: 10}, s.err
}

func problemCode(err error) domain.ProblemCode {
	var problem domain.Problem
	if errors.As(err, &problem) {
		return problem.Code
	}
	return ""
}

// TestNothingIsEncryptedForNobody: a document and at least one recipient,
// or the command is not run.
func TestNothingIsEncryptedForNobody(t *testing.T) {
	envelopes := &scriptedEnvelopes{}
	encrypt := application.NewEncryptForRecipients(envelopes)
	for intent, want := range map[*domain.EncryptionIntent]domain.ProblemCode{
		{Recipients: []string{"/tmp/anna.pem"}}: domain.ProblemMissingDocument,
		{DocumentPath: "/tmp/offerta.pdf"}:      domain.ProblemMissingRecipient,
	} {
		if _, err := encrypt.Execute(context.Background(), *intent); problemCode(err) != want {
			t.Errorf("%+v: %v, want %s", *intent, err, want)
		}
	}
	if len(envelopes.encrypted) != 0 {
		t.Fatal("an incomplete intent reached the command")
	}
	sealed, err := encrypt.Execute(context.Background(), domain.EncryptionIntent{DocumentPath: "/tmp/offerta.pdf", Recipients: []string{"/tmp/anna.pem"}})
	if err != nil || sealed.Path != "/tmp/offerta.pdf.p7e" || len(envelopes.encrypted) != 1 {
		t.Errorf("%+v, %v", sealed, err)
	}
}

// TestAnEnvelopeNeedsAKeyThatCanOpenIt: an envelope and a key, a card that
// can be used, or the command is not run.
func TestAnEnvelopeNeedsAKeyThatCanOpenIt(t *testing.T) {
	envelopes := &scriptedEnvelopes{}
	open := application.NewOpenEnvelope(envelopes)
	file := domain.CertificateFile{Path: "/tmp/mario.p12"}
	for name, test := range map[string]struct {
		intent domain.OpeningIntent
		want   domain.ProblemCode
	}{
		"no envelope":   {domain.OpeningIntent{Key: file}, domain.ProblemMissingDocument},
		"no key":        {domain.OpeningIntent{EnvelopePath: "/tmp/o.p7e"}, domain.ProblemMissingKey},
		"no PIN":        {domain.OpeningIntent{EnvelopePath: "/tmp/o.p7e", Card: domain.CardKey{Fingerprint: "ab"}}, domain.ProblemMissingPIN},
		"a locked card": {domain.OpeningIntent{EnvelopePath: "/tmp/o.p7e", Card: domain.CardKey{Fingerprint: "ab", PIN: "1", State: signing.PINLocked}}, domain.ProblemCardLocked},
	} {
		if _, err := open.Execute(context.Background(), test.intent); problemCode(err) != test.want {
			t.Errorf("%s: %v, want %s", name, err, test.want)
		}
	}
	if len(envelopes.opened) != 0 {
		t.Fatal("an incomplete intent reached the command")
	}
	opened, err := open.Execute(context.Background(), domain.OpeningIntent{EnvelopePath: "/tmp/o.p7e", Key: file})
	if err != nil || opened.Path != "/tmp/offerta.pdf" {
		t.Errorf("%+v, %v", opened, err)
	}
	envelopes.err = domain.Problem{Code: domain.ProblemWrongPIN}
	if _, err := open.Execute(context.Background(), domain.OpeningIntent{EnvelopePath: "/tmp/o.p7e", Key: file}); problemCode(err) != domain.ProblemWrongPIN {
		t.Errorf("the opener's refusal is lost: %v", err)
	}
}
