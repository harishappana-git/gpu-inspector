package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data, _ := Sign([]byte(`{"kind":"fixture"}`), priv)
	if _, err := Verify(data, pub); err != nil {
		t.Fatal(err)
	}
	var e Envelope
	_ = json.Unmarshal(data, &e)
	e.Payload = "e30="
	bad, _ := json.Marshal(e)
	if _, err := Verify(bad, pub); err == nil {
		t.Fatal("tamper accepted")
	}
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(data, wrong); err == nil {
		t.Fatal("wrong key accepted")
	}
	if err := Decode([]byte(`{} {}`), &Envelope{}); err == nil {
		t.Fatal("extra JSON accepted")
	}
}

func TestSignedDecodePreservesExactIntegerPayload(t *testing.T) {
	payload := []byte(`{"counter":9007199254740993,"largest":18446744073709551615}`)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(envelope, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(verified, payload) {
		t.Fatal("signature verification changed payload bytes")
	}
	var values map[string]any
	if err := Decode(verified, &values); err != nil {
		t.Fatal(err)
	}
	if values["counter"] != json.Number("9007199254740993") || values["largest"] != json.Number("18446744073709551615") {
		t.Fatalf("exact signed integer evidence changed: %#v", values)
	}
}

func TestDecodeRejectsDuplicateMembersRecursively(t *testing.T) {
	tests := []string{
		`{"name":1,"name":2}`,
		`{"name":1,"name":1}`,
		`{"outer":{"value":true,"value":false}}`,
		`[{"array_member":"a","array_member":"b"}]`,
		`{"outer":[{"nested":{"n":1,"n":2}}]}`,
		`{"name":1,"\u006eame":2}`,
	}
	for _, data := range tests {
		var decoded any
		if err := Decode([]byte(data), &decoded); err == nil {
			t.Fatalf("duplicate names accepted: %s", data)
		}
	}
	for _, data := range []string{`{"a":{"name":1},"b":{"name":2}}`, `[{"name":1},{"name":2}]`, `{"items":[],"nothing":null,"number":1.2}`} {
		var decoded any
		if err := Decode([]byte(data), &decoded); err != nil {
			t.Fatalf("distinct object scopes rejected: %v", err)
		}
	}
}
func TestDecodeRejectsExcessiveDepth(t *testing.T) {
	data := strings.Repeat("[", maxJSONDepth+2) + "0" + strings.Repeat("]", maxJSONDepth+2)
	var decoded any
	if err := Decode([]byte(data), &decoded); err == nil {
		t.Fatal("excessive JSON nesting accepted")
	}
}
func TestDuplicateEnvelopeMembersRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed, err := Sign([]byte(`{"synthetic":"fixture"}`), priv)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append(append([]byte(nil), signed[:len(signed)-1]...), []byte(`,"algorithm":"Ed25519"}`)...)
	if _, err := Verify(duplicate, pub); err == nil {
		t.Fatal("ambiguous signed envelope accepted")
	}
}
func TestSignedPayloadBudgetFitsEnvelope(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload := bytes.Repeat([]byte("x"), MaxPayloadBytes)
	signed, err := Sign(payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed) > MaxDocumentBytes {
		t.Fatalf("maximum signed payload produced oversized envelope: %d", len(signed))
	}
	verified, err := Verify(signed, pub)
	if err != nil || !bytes.Equal(verified, payload) {
		t.Fatalf("maximum valid envelope cannot be verified: %v", err)
	}
	oversized := append(payload, 'x')
	if _, err := Sign(oversized, priv); err == nil {
		t.Fatal("oversized payload signed")
	}
	// An externally signed envelope must obey the same payload cap, even when its
	// base64 representation still fits inside the document's outer limit.
	external, err := json.Marshal(Envelope{Payload: base64.StdEncoding.EncodeToString(oversized), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, oversized)), Algorithm: "Ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	if len(external) > MaxDocumentBytes {
		t.Fatal("test did not isolate the inner payload limit")
	}
	if _, err := Verify(external, pub); err == nil {
		t.Fatal("external signature bypassed payload size policy")
	}
}
func TestDecodeDocumentSizeBound(t *testing.T) {
	var decoded any
	if err := Decode(bytes.Repeat([]byte(" "), MaxDocumentBytes+1), &decoded); err == nil {
		t.Fatal("oversized JSON document accepted")
	}
}
