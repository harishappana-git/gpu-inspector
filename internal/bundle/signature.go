// Package bundle authenticates exact payload bytes with an explicitly trusted
// Ed25519 key. It does not turn an untrusted rental host into a trusted verifier.
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

const MaxDocumentBytes = 4 << 20

// Reserve room for base64's 4/3 expansion, the signature, JSON fields and
// formatting. A signed payload at this limit fits inside MaxDocumentBytes.
const MaxPayloadBytes = MaxDocumentBytes / 2
const maxJSONDepth = 128

// CheckUniqueJSON validates JSON member uniqueness, syntax and bounded nesting.
// It leaves unknown-field policy and byte limits to the caller so larger local
// evidence reports can share the same ambiguity check as signed envelopes.
func CheckUniqueJSON(data []byte) error { return validateJSONMembers(data) }

type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	Algorithm string `json:"algorithm"`
}

func Decode(data []byte, dest any) error {
	if len(data) > MaxDocumentBytes {
		return errors.New("document exceeds size limit")
	}
	if err := validateJSONMembers(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	d.DisallowUnknownFields()
	if err := d.Decode(dest); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing data in document")
	}
	return nil
}

// encoding/json otherwise accepts repeated object names and uses the last
// value. Reject them before decoding either signed envelopes or their payloads.
// Tokens decode escapes first, so "name" and "\u006eame" are duplicates too.
func validateJSONMembers(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > maxJSONDepth {
			return errors.New("JSON nesting exceeds supported depth")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, container := token.(json.Delim)
		if !container {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object member is not a string")
				}
				if seen[key] {
					return fmt.Errorf("duplicate JSON object member near byte %d", d.InputOffset())
				}
				seen[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return errors.New("invalid JSON object terminator")
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return errors.New("invalid JSON array terminator")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing data in document")
	}
	return nil
}
func ReadLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("expected regular file")
	}
	if info.Size() > limit {
		return nil, errors.New("file exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds size limit")
	}
	return data, err
}
func Verify(data []byte, key ed25519.PublicKey) ([]byte, error) {
	var envelope Envelope
	if err := Decode(data, &envelope); err != nil {
		return nil, err
	}
	if envelope.Algorithm != "Ed25519" {
		return nil, errors.New("unsupported signing algorithm")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxPayloadBytes {
		return nil, errors.New("signed payload exceeds size limit")
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, payload, sig) {
		return nil, errors.New("signature verification failed")
	}
	return payload, nil
}
func Sign(data []byte, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key")
	}
	if len(data) > MaxPayloadBytes {
		return nil, errors.New("payload exceeds size limit")
	}
	envelope, err := json.MarshalIndent(Envelope{Payload: base64.StdEncoding.EncodeToString(data), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, data)), Algorithm: "Ed25519"}, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(envelope) > MaxDocumentBytes {
		return nil, errors.New("signed envelope exceeds document limit")
	}
	return envelope, nil
}
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := ReadLimited(path, 16384)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one PEM public key")
	}
	value, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := value.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("expected Ed25519 public key")
	}
	return key, nil
}
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private key permissions must be 0600 or stricter")
	}
	data, err := ReadLimited(path, 16384)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one PEM private key")
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := value.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("expected Ed25519 private key")
	}
	return key, nil
}
func GenerateKeys(dir string) error {
	if err := os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("key directory must be new: %w", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err = WriteNew(dir+"/private.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600); err != nil {
		return err
	}
	return WriteNew(dir+"/public.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0600)
}
func WriteNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	return errors.Join(werr, serr, cerr)
}
