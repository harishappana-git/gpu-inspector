package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harishappana/gpu-inspector/internal/bundle"
)

func TestSignVerifiesExpectedKeyPairBeforePublishing(t *testing.T) {
	root := t.TempDir()
	keys := filepath.Join(root, "signing-keys")
	otherKeys := filepath.Join(root, "other-signing-keys")
	for _, dir := range []string{keys, otherKeys} {
		if err := bundle.GenerateKeys(dir); err != nil {
			t.Fatal(err)
		}
	}
	payload := []byte("{\n  \"synthetic_fixture_only\": true,\n  \"qualified\": false\n}\n")
	input := filepath.Join(root, "synthetic-payload.json")
	if err := os.WriteFile(input, payload, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, verificationKey string
		wantSuccess           bool
	}{
		{"matching pair", filepath.Join(keys, "public.pem"), true},
		{"different public key", filepath.Join(otherKeys, "public.pem"), false},
		{"private key in public slot", filepath.Join(keys, "private.pem"), false},
		{"missing verification key", filepath.Join(root, "missing.pem"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "signed.json")
			code, stdout, stderr := invoke(t, "sign", "--input", input, "--key", filepath.Join(keys, "private.pem"), "--verify-public-key", tc.verificationKey, "--output", dest)
			if tc.wantSuccess {
				if code != 0 {
					t.Fatalf("matching pair rejected: %s", stderr)
				}
				envelope, err := os.ReadFile(dest)
				if err != nil {
					t.Fatal(err)
				}
				public, err := bundle.LoadPublicKey(tc.verificationKey)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := bundle.Verify(envelope, public)
				if err != nil || !bytes.Equal(decoded, payload) {
					t.Fatalf("signed envelope changed exact payload bytes: %v", err)
				}
				if !strings.Contains(stdout, "Qualification is a separate") {
					t.Fatal("local key pairing was represented as qualification")
				}
			} else {
				if code != 1 || stderr == "" {
					t.Fatalf("invalid pairing accepted: code=%d stderr=%q", code, stderr)
				}
				if _, err := os.Lstat(dest); !os.IsNotExist(err) {
					t.Fatalf("failed pairing left a signed output: %v", err)
				}
				if strings.Contains(stdout, "Signed exact payload") {
					t.Fatal("failure reported successful publication")
				}
			}
		})
	}
}

func TestSignPairMismatchPreservesExistingDestination(t *testing.T) {
	root := t.TempDir()
	keys, otherKeys := filepath.Join(root, "keys"), filepath.Join(root, "other-keys")
	for _, dir := range []string{keys, otherKeys} {
		if err := bundle.GenerateKeys(dir); err != nil {
			t.Fatal(err)
		}
	}
	input, dest := filepath.Join(root, "payload.json"), filepath.Join(root, "existing.json")
	if err := os.WriteFile(input, []byte("{\"synthetic\":true}"), 0600); err != nil {
		t.Fatal(err)
	}
	prior := []byte("Previously retained user evidence; preserve exact bytes")
	if err := os.WriteFile(dest, prior, 0600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := invoke(t, "sign", "--input", input, "--key", filepath.Join(keys, "private.pem"), "--verify-public-key", filepath.Join(otherKeys, "public.pem"), "--output", dest)
	if code != 1 || !strings.Contains(stderr, "does not match") {
		t.Fatalf("mismatched key pair was not rejected before publication: %d %s", code, stderr)
	}
	after, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(after, prior) {
		t.Fatal("key mismatch changed pre-existing evidence")
	}
}
