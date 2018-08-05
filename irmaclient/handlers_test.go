package irmaclient

import (
	"encoding/json"
	"testing"

	"github.com/mhe/gabi"
	"github.com/pkg/errors"
	"github.com/privacybydesign/irmago"
)

type TestClientHandler struct {
	t *testing.T
	c chan error
}

func (i *TestClientHandler) UpdateConfiguration(new *irma.IrmaIdentifierSet) {}
func (i *TestClientHandler) UpdateAttributes()                               {}
func (i *TestClientHandler) EnrollmentSuccess(manager irma.SchemeManagerIdentifier) {
	select {
	case i.c <- nil: // nop
	default: // nop
	}
}
func (i *TestClientHandler) EnrollmentFailure(manager irma.SchemeManagerIdentifier, err error) {
	select {
	case i.c <- err: // nop
	default:
		i.t.Fatal(err)
	}
}
func (i *TestClientHandler) ChangePinSuccess(manager irma.SchemeManagerIdentifier) {
	select {
	case i.c <- nil: // nop
	default: // nop
	}
}
func (i *TestClientHandler) ChangePinFailure(manager irma.SchemeManagerIdentifier, err error) {
	select {
	case i.c <- err: //nop
	default:
		i.t.Fatal(err)
	}
}
func (i *TestClientHandler) ChangePinIncorrect(manager irma.SchemeManagerIdentifier, attempts int) {
	err := errors.New("incorrect pin")
	select {
	case i.c <- err: //nop
	default:
		i.t.Fatal(err)
	}
}
func (i *TestClientHandler) ChangePinBlocked(manager irma.SchemeManagerIdentifier, timeout int) {
	err := errors.New("blocked account")
	select {
	case i.c <- err: //nop
	default:
		i.t.Fatal(err)
	}
}

type TestHandler struct {
	t      *testing.T
	c      chan *SessionResult
	client *Client
}

func (th TestHandler) KeyshareEnrollmentIncomplete(manager irma.SchemeManagerIdentifier) {
	th.Failure(&irma.SessionError{Err: errors.New("KeyshareEnrollmentIncomplete")})
}
func (th TestHandler) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {
	th.Failure(&irma.SessionError{Err: errors.New("KeyshareBlocked")})
}
func (th TestHandler) KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier) {
	th.Failure(&irma.SessionError{Err: errors.Errorf("Missing keyshare server %s", manager.String())})
}
func (th TestHandler) KeyshareEnrollmentDeleted(manager irma.SchemeManagerIdentifier) {
	th.Failure(&irma.SessionError{Err: errors.Errorf("Keyshare enrollment deleted for %s", manager.String())})
}
func (th TestHandler) StatusUpdate(action irma.Action, status irma.Status) {}
func (th TestHandler) Success(result string) {
	th.c <- nil
}
func (th TestHandler) Cancelled() {
	th.Failure(&irma.SessionError{Err: errors.New("Cancelled")})
}
func (th TestHandler) Failure(err *irma.SessionError) {
	th.t.Logf("Session failed: %+v\n", *err)
	select {
	case th.c <- &SessionResult{Err: err}:
	default:
		th.t.Fatal(err)
	}
}
func (th TestHandler) UnsatisfiableRequest(serverName string, missing irma.AttributeDisjunctionList) {
	th.Failure(&irma.SessionError{
		ErrorType: irma.ErrorType("UnsatisfiableRequest"),
	})
}
func (th TestHandler) RequestVerificationPermission(request irma.DisclosureRequest, ServerName string, callback PermissionHandler) {
	choice := &irma.DisclosureChoice{
		Attributes: []*irma.AttributeIdentifier{},
	}
	var candidates []*irma.AttributeIdentifier
	for _, disjunction := range request.Content {
		candidates = th.client.Candidates(disjunction)
		if len(candidates) == 0 {
			th.Failure(&irma.SessionError{Err: errors.New("No disclosure candidates found")})
		}
		choice.Attributes = append(choice.Attributes, candidates[0])
	}
	callback(true, choice)
}
func (th TestHandler) RequestIssuancePermission(request irma.IssuanceRequest, ServerName string, callback PermissionHandler) {
	dreq := irma.DisclosureRequest{
		BaseRequest: request.BaseRequest,
		Content:     request.Disclose,
	}
	th.RequestVerificationPermission(dreq, ServerName, callback)
}
func (th TestHandler) RequestSignaturePermission(request irma.SignatureRequest, ServerName string, callback PermissionHandler) {
	th.RequestVerificationPermission(request.DisclosureRequest, ServerName, callback)
}
func (th TestHandler) RequestSchemeManagerPermission(manager *irma.SchemeManager, callback func(proceed bool)) {
	callback(true)
}
func (th TestHandler) RequestPin(remainingAttempts int, callback PinHandler) {
	callback(true, "12345")
}

type SessionResult struct {
	Err                error
	SignatureResult    *irma.SignedMessage
	VerificationResult gabi.ProofList
}

// ManualTestHandler embeds a TestHandler to inherit its methods.
// Below we overwrite the methods that require behaviour specific to manual settings.
type ManualTestHandler struct {
	TestHandler
	action irma.Action
}

func (th *ManualTestHandler) StatusUpdate(action irma.Action, status irma.Status) {
	th.action = action
}

func (th *ManualTestHandler) Success(result string) {
	if len(result) == 0 {
		th.c <- nil
		return
	}

	var err error
	retval := &SessionResult{}
	switch th.action {
	case irma.ActionSigning:
		retval.SignatureResult = &irma.SignedMessage{}
		err = json.Unmarshal([]byte(result), retval.SignatureResult)
	case irma.ActionDisclosing:
		proofs := []*gabi.ProofD{}
		err = json.Unmarshal([]byte(result), &proofs)
		retval.VerificationResult = make(gabi.ProofList, len(proofs))
		for i, proof := range proofs {
			retval.VerificationResult[i] = proof
		}
	}
	if err != nil {
		th.Failure(&irma.SessionError{
			Err:       err,
			ErrorType: irma.ErrorSerialization,
		})
		return
	}

	th.c <- retval
}
func (th *ManualTestHandler) RequestSignaturePermission(request irma.SignatureRequest, requesterName string, ph PermissionHandler) {
	th.RequestVerificationPermission(request.DisclosureRequest, requesterName, ph)
}
func (th *ManualTestHandler) RequestIssuancePermission(request irma.IssuanceRequest, issuerName string, ph PermissionHandler) {
	ph(true, nil)
}

// These handlers should not be called, fail test if they are called
func (th *ManualTestHandler) RequestSchemeManagerPermission(manager *irma.SchemeManager, callback func(proceed bool)) {
	th.Failure(&irma.SessionError{Err: errors.New("Unexpected session type")})
}
func (th *ManualTestHandler) RequestVerificationPermission(request irma.DisclosureRequest, verifierName string, ph PermissionHandler) {
	var attributes []*irma.AttributeIdentifier
	for _, cand := range request.Candidates {
		attributes = append(attributes, cand[0])
	}
	c := irma.DisclosureChoice{attributes}
	ph(true, &c)
}
