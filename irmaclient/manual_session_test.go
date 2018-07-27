package irmaclient

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

// Create a ManualSessionHandler for unit tests
func createManualSessionHandler(t *testing.T, client *Client) *ManualSessionHandler {
	return &ManualSessionHandler{
		TestHandler: TestHandler{
			t:      t,
			c:      make(chan *SessionResult),
			client: client,
		},
	}
}

func manualSessionHelper(t *testing.T, client *Client, h *ManualSessionHandler, request string, verifyAs string, corrupt bool) *irma.SignatureProofResult {
	init := client == nil
	if init {
		client = parseStorage(t)
	}

	client.NewSession(request, h)

	result := <-h.c
	if result.Err != nil {
		require.NoError(t, result.Err)
	}

	verifyasRequest := &irma.SignatureRequest{}
	err := json.Unmarshal([]byte(verifyAs), verifyasRequest)
	require.NoError(t, err)
	if corrupt {
		// Interesting: modifying C results in INVALID_CRYPTO; modifying A or an attribute results in INVALID_TIMESTAMP
		i := result.Result.Signature[0].(*gabi.ProofD).C
		i.Add(i, big.NewInt(16))
	}
	return result.Result.Verify(client.Configuration, verifyasRequest)
}

func TestManualSession(t *testing.T) {
	request := "{\"nonce\": 42, \"context\": 1337, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	ms := createManualSessionHandler(t, nil)
	result := manualSessionHelper(t, nil, ms, request, request, false)

	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
	require.Equal(t, irma.AttributeProofStatusPresent, result.ToAttributeResultList()[0].AttributeProofStatus)

	test.ClearTestStorage(t)
}

// Test if proof verification fails with status 'ERROR_CRYPTO' if we verify it with an invalid nonce
func TestManualSessionInvalidNonce(t *testing.T) {
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	invalidRequest := "{\"nonce\": 1, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	ms := createManualSessionHandler(t, nil)
	result := manualSessionHelper(t, nil, ms, request, invalidRequest, false)

	require.Equal(t, irma.ProofStatusUnmatchedRequest, result.ProofStatus)

	test.ClearTestStorage(t)
}

// Test if proof verification fails with status 'MISSING_ATTRIBUTES' if we provide it with a non-matching signature request
func TestManualSessionInvalidRequest(t *testing.T) {
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	invalidRequest := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.university\"]}]}"
	ms := createManualSessionHandler(t, nil)
	result := manualSessionHelper(t, nil, ms, request, invalidRequest, false)
	list := result.ToAttributeResultList()

	require.Equal(t, irma.ProofStatusMissingAttributes, result.ProofStatus)
	// First attribute result is MISSING, because it is in the request but not disclosed
	require.Equal(t, irma.AttributeProofStatusMissing, list[0].AttributeProofStatus)
	// Second attribute result is EXTRA, since it is disclosed, but not matching the sigrequest
	require.Equal(t, irma.AttributeProofStatusExtra, list[1].AttributeProofStatus)

	test.ClearTestStorage(t)
}

// Test if proof verification fails with status 'MISSING_ATTRIBUTES' if we provide it with invalid attribute values
func TestManualSessionInvalidAttributeValue(t *testing.T) {
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":{\"irma-demo.RU.studentCard.studentID\": \"456\"}}]}"
	invalidRequest := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":{\"irma-demo.RU.studentCard.studentID\": \"123\"}}]}"
	ms := createManualSessionHandler(t, nil)
	result := manualSessionHelper(t, nil, ms, request, invalidRequest, false)

	require.Equal(t, irma.ProofStatusMissingAttributes, result.ProofStatus)
	require.Equal(t, irma.AttributeProofStatusInvalidValue, result.ToAttributeResultList()[0].AttributeProofStatus)

	test.ClearTestStorage(t)
}

func TestManualKeyShareSession(t *testing.T) {
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"test.test.mijnirma.email\"]}]}"
	ms := createManualSessionHandler(t, nil)
	result := manualSessionHelper(t, nil, ms, request, request, false)

	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)

	test.ClearTestStorage(t)
}

func TestManualSessionMultiProof(t *testing.T) {
	client := parseStorage(t)

	// First, we need to issue an extra credential (BSN)
	jwtcontents := getIssuanceJwt("testip", true, "")
	sessionHelper(t, jwtcontents, "issue", client)

	// Request to sign with both BSN and StudentID
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]},{\"label\":\"BSN\",\"attributes\":[\"irma-demo.MijnOverheid.root.BSN\"]}]}"

	ms := createManualSessionHandler(t, client)
	result := manualSessionHelper(t, client, ms, request, request, false)

	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
	list := result.ToAttributeResultList()
	require.Equal(t, irma.AttributeProofStatusPresent, list[0].AttributeProofStatus)
	require.Equal(t, irma.AttributeProofStatusPresent, list[1].AttributeProofStatus)

	test.ClearTestStorage(t)
}

func TestManualSessionInvalidProof(t *testing.T) {
	request := "{\"nonce\": 0, \"context\": 0, \"type\": \"signing\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	ms := createManualSessionHandler(t, nil)
	result := manualSessionHelper(t, nil, ms, request, request, true)

	require.Equal(t, irma.ProofStatusInvalidCrypto, result.ProofStatus)

	test.ClearTestStorage(t)
}
