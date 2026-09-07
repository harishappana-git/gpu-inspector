package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/harishappana/gpu-inspector/internal/campaignimport"
)

func TestImportCommandReturnsPrivateReviewIndexJSONForPartialCampaign(t *testing.T) {
	files := map[string][]byte{"campaign-status.json": []byte(`{"synthetic_fixture":true,"status":"setup_failed"}`), "remaining-checklist.json": []byte(`{"remaining":true}`), "remaining-checklist.txt": []byte("Synthetic fixture: H100 acceptance still required")}
	qualified := false
	m := campaignimport.Manifest{SchemaVersion: 1, CampaignID: "synthetic-cli-fixture", ReleaseQualified: &qualified}
	for name, data := range files {
		hash := sha256.Sum256(data)
		m.Files = append(m.Files, campaignimport.File{Path: name, SHA256: hex.EncodeToString(hash[:]), Bytes: int64(len(data))})
	}
	manifest, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	files["campaign-manifest.json"] = manifest
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for name, data := range files {
		w, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	source, output := filepath.Join(root, "fixture.zip"), filepath.Join(root, "review")
	if err := os.WriteFile(source, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := invoke(t, "import", "--archive", source, "--output", output, "--json")
	if code != 0 {
		t.Fatalf("import command failed: %d %s", code, stderr)
	}
	var result campaignimport.Result
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if result.IndexPath != filepath.Join(output, "index.html") || result.ReleaseQualified || len(result.Reports) != 0 {
		t.Fatalf("incorrect controller import contract: %+v", result)
	}
	if _, err := os.Stat(result.IndexPath); err != nil {
		t.Fatal(err)
	}
}

func TestImportCommandRejectsMissingAndUnexpectedArguments(t *testing.T) {
	for _, args := range [][]string{{}, {"--archive", "missing.zip"}, {"--output", "unused"}, {"--archive", "missing.zip", "--output", "unused", "extra"}, {"--execute"}} {
		var stdout, stderr bytes.Buffer
		if err := importCommand(context.Background(), args, &stdout, &stderr); err == nil {
			t.Fatalf("invalid import flags accepted: %v", args)
		}
	}
}
