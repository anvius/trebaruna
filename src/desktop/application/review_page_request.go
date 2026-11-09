package application

import (
	"context"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// PageSession is one web page request being answered: proposals come out,
// decisions go in, and the outcome ends it.
type PageSession interface {
	Next() (domain.PageStep, error)
	Decide(decision domain.PageDecision) error
	Close() error
}

// PageRequests opens a session for an afirma:// URI.
type PageRequests interface {
	Open(ctx context.Context, uri string) (PageSession, error)
}

// ReviewPageRequest is the use case behind the approval window: it opens the
// session the window drives, and refuses an incomplete approval before it
// reaches the command.
type ReviewPageRequest struct {
	requests PageRequests
}

// NewReviewPageRequest wires the use case.
func NewReviewPageRequest(requests PageRequests) *ReviewPageRequest {
	return &ReviewPageRequest{requests: requests}
}

// Execute opens the session for the URI.
func (u *ReviewPageRequest) Execute(ctx context.Context, uri string) (PageSession, error) {
	session, err := u.requests.Open(ctx, uri)
	if err != nil {
		return nil, err
	}
	return &validatingSession{inner: session}, nil
}

// validatingSession checks each decision against the proposal it answers.
type validatingSession struct {
	inner    PageSession
	proposal domain.PageProposal
	known    bool
}

// Next reads the next step and keeps the proposal it carries.
func (s *validatingSession) Next() (domain.PageStep, error) {
	step, err := s.inner.Next()
	if step.Proposal != nil {
		s.proposal, s.known = *step.Proposal, true
	}
	return step, err
}

// Decide refuses an approval the proposal does not allow.
func (s *validatingSession) Decide(decision domain.PageDecision) error {
	if s.known {
		if err := decision.Validate(s.proposal); err != nil {
			return err
		}
	}
	return s.inner.Decide(decision)
}

// Close ends the session.
func (s *validatingSession) Close() error { return s.inner.Close() }
