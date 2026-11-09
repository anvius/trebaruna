package application

import (
	"context"
	"fmt"
)

// LocalChannelCertificate makes, installs and removes the certificate the
// afirma:// local channel serves (ADR-0019).
type LocalChannelCertificate interface {
	Run(ctx context.Context, action string) (string, error)
}

// ManageLocalChannel is the use case behind the window's local channel
// choice: what is installed, installing it for the user, removing it.
type ManageLocalChannel struct {
	certificate LocalChannelCertificate
}

// NewManageLocalChannel wires the use case.
func NewManageLocalChannel(certificate LocalChannelCertificate) *ManageLocalChannel {
	return &ManageLocalChannel{certificate: certificate}
}

// Execute runs status, install or remove and returns what it says.
func (u *ManageLocalChannel) Execute(ctx context.Context, action string) (string, error) {
	switch action {
	case "status", "install", "remove":
		return u.certificate.Run(ctx, action)
	}
	return "", fmt.Errorf("unknown local channel action %q", action)
}
