// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	server, err := newDemoServer(log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("newDemoServer() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	server.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte(`"status":"ok"`)) {
		t.Fatalf("health body = %s, want status ok", recorder.Body.String())
	}
}

func TestCallToolRedactsSecretsAndVerifiesSignature(t *testing.T) {
	server, err := newDemoServer(log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("newDemoServer() error = %v", err)
	}

	payload, err := json.Marshal(toolCallRequest{
		SessionToken:    server.session.Token,
		ToolName:        "docs.secret-demo",
		ToolDescription: "Return a sample response",
		Input:           "show the redaction path",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/call-tool", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	server.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("call-tool status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte(`[REDACTED_API_KEY]`)) {
		t.Fatalf("call-tool body = %s, want redacted api key", recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte(`"signature_valid":true`)) {
		t.Fatalf("call-tool body = %s, want signature_valid true", recorder.Body.String())
	}
}
