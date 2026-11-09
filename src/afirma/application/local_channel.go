package application

import (
	"context"
	"errors"
	"strings"
	"sync"

	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
)

// waitAnswer is what protocol 4.1 answers while an operation runs.
const waitAnswer = "#wait"

// AnswerLocalChannel is the use case behind the WebSocket channel (D.1):
// each message the page sends gets one answer. An echo is answered "OK";
// an operation runs as from the intermediate server, approved by the
// person, its answer sent back on the socket. Over protocol 4 every
// message must name the session the page opened; over 4.1 an operation
// answers "#wait" and the page asks for its result with getresult.
type AnswerLocalChannel struct {
	page    *AnswerPage
	channel domain.LocalChannel

	mutex   sync.Mutex
	running bool
	result  *string
}

// NewAnswerLocalChannel wires the use case for one channel.
func NewAnswerLocalChannel(page *AnswerPage, channel domain.LocalChannel) *AnswerLocalChannel {
	return &AnswerLocalChannel{page: page, channel: channel}
}

// Answer is the answer to one message of the page.
func (u *AnswerLocalChannel) Answer(ctx context.Context, message string) string {
	if u.channel.Version >= 4 && u.channel.SessionID != "" && domain.MessageSession(message) != u.channel.SessionID {
		return domain.Failure{Code: domain.InvalidSessionID}.Answer()
	}
	switch {
	case strings.HasPrefix(message, "echo="):
		return "OK"
	case strings.HasPrefix(message, "getresult"):
		return u.takeResult()
	}
	invocation, err := domain.ParseInvocation(message)
	if err != nil {
		return failureText(err)
	}
	invocation = domain.BySocket(invocation, u.channel)
	if !u.channel.Asynchronous {
		return u.run(ctx, invocation)
	}
	u.mutex.Lock()
	defer u.mutex.Unlock()
	if u.running {
		return waitAnswer
	}
	u.running, u.result = true, nil
	go func() {
		text := u.run(context.WithoutCancel(ctx), invocation)
		u.mutex.Lock()
		u.running, u.result = false, &text
		u.mutex.Unlock()
	}()
	return waitAnswer
}

// takeResult is the finished operation's answer, once, or "#wait".
func (u *AnswerLocalChannel) takeResult() string {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	if u.result == nil {
		return waitAnswer
	}
	text := *u.result
	u.result = nil
	return text
}

// run executes an operation and returns its answer as the page reads it.
func (u *AnswerLocalChannel) run(ctx context.Context, invocation domain.Invocation) string {
	if invocation.Operation == domain.WebSocket || invocation.Operation == domain.Service {
		return domain.Failure{Code: domain.UnsupportedOperation}.Answer()
	}
	answer, err := u.page.Execute(ctx, invocation)
	if text := answer.Text(); text != "" {
		return text
	}
	return failureText(err)
}

func failureText(err error) string {
	var failure domain.Failure
	if !errors.As(err, &failure) {
		failure = domain.Failure{Code: domain.SignatureFailed, Cause: err.Error()}
	}
	return failure.Answer()
}
