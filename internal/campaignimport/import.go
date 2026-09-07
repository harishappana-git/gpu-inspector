package campaignimport

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/harishappana/gpu-inspector/internal/bundle"
	"github.com/harishappana/gpu-inspector/internal/privatefs"
	"github.com/harishappana/gpu-inspector/internal/report"
)

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

// Every campaign artifact is UTF-8 text or JSON. Reject accidentally renamed
// binaries and literal private-key PEM material even inside an allowed log.
// Only a bounded cross-chunk tail is retained.
type artifactTextGuard struct {
	utf8Tail []byte
	keyTail  []byte
}

func (g *artifactTextGuard) Write(p []byte) (int, error) {
	if bytes.IndexByte(p, 0) >= 0 {
		return 0, fmt.Errorf("campaign artifact contains binary NUL data")
	}
	keyData := append(append([]byte(nil), g.keyTail...), p...)
	if bytes.Contains(keyData, []byte("PRIVATE KEY-----")) {
		return 0, fmt.Errorf("campaign artifact contains private-key PEM material")
	}
	if len(keyData) > 32 {
		keyData = keyData[len(keyData)-32:]
	}
	g.keyTail = append(g.keyTail[:0], keyData...)
	data := append(append([]byte(nil), g.utf8Tail...), p...)
	g.utf8Tail = nil
	for len(data) > 0 {
		if !utf8.FullRune(data) {
			g.utf8Tail = append(g.utf8Tail, data...)
			break
		}
		r, n := utf8.DecodeRune(data)
		if r == utf8.RuneError && n == 1 {
			return 0, fmt.Errorf("campaign artifact is not UTF-8 text")
		}
		data = data[n:]
	}
	return len(p), nil
}
func (g *artifactTextGuard) finish() error {
	if len(g.utf8Tail) != 0 {
		return fmt.Errorf("campaign artifact ends with incomplete UTF-8")
	}
	return nil
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > 64<<10 {
		p = p[:64<<10]
	}
	return r.r.Read(p)
}

// Check the small ZIP directory footer before archive/zip allocates one object
// per entry. ZIP64, multi-disk, oversized directories, and trailing data are not
// part of this bounded campaign format.
func zipEntryCount(f *os.File, size int64) (int, error) {
	if size < 22 || size > MaxArchiveBytes {
		return 0, fmt.Errorf("campaign archive size is out of bounds")
	}
	n := int64(22 + 65535)
	if size < n {
		n = size
	}
	tail := make([]byte, n)
	if _, err := f.ReadAt(tail, size-n); err != nil {
		return 0, err
	}
	for i := len(tail) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) != 0x06054b50 {
			continue
		}
		p := tail[i:]
		if int(binary.LittleEndian.Uint16(p[20:]))+22 != len(p) {
			continue
		}
		count := int(binary.LittleEndian.Uint16(p[10:]))
		dirSize, dirOffset := int64(binary.LittleEndian.Uint32(p[12:])), int64(binary.LittleEndian.Uint32(p[16:]))
		if binary.LittleEndian.Uint16(p[4:]) != 0 || binary.LittleEndian.Uint16(p[6:]) != 0 || int(binary.LittleEndian.Uint16(p[8:])) != count || count < 4 || count > MaxFiles || dirSize > 2<<20 || dirOffset+dirSize != size-n+int64(i) {
			return 0, fmt.Errorf("unsupported or oversized ZIP directory")
		}
		return count, nil
	}
	return 0, fmt.Errorf("bounded ZIP directory footer not found")
}

func inspectZIP(f *os.File, size int64) (map[string]*zip.File, error) {
	count, err := zipEntryCount(f, size)
	if err != nil {
		return nil, err
	}
	z, err := zip.NewReader(f, size)
	if err != nil {
		return nil, err
	}
	if len(z.File) != count {
		return nil, fmt.Errorf("ZIP directory count differs from footer")
	}
	files := map[string]*zip.File{}
	seen := map[string]bool{}
	var total uint64
	for _, entry := range z.File {
		name := entry.Name
		folded := strings.ToLower(name)
		if !allowedPath(name) || seen[folded] || !entry.Mode().IsRegular() || entry.ExternalAttrs&0x400 != 0 || entry.Flags&1 != 0 || (entry.Method != zip.Store && entry.Method != zip.Deflate) {
			return nil, fmt.Errorf("archive contains an unsupported, duplicate or unsafe entry %q", name)
		}
		seen[folded] = true
		limit := uint64(MaxFileBytes)
		if name == "campaign-manifest.json" {
			limit = uint64(MaxManifestBytes)
		}
		if entry.UncompressedSize64 > limit || entry.CompressedSize64 > uint64(MaxArchiveBytes) || (entry.UncompressedSize64 > 0 && (entry.CompressedSize64 == 0 || entry.UncompressedSize64 > entry.CompressedSize64*MaxCompressionRatio)) {
			return nil, fmt.Errorf("archive entry exceeds size or compression limit: %s", name)
		}
		total += entry.UncompressedSize64
		if total > uint64(MaxTotalBytes) {
			return nil, fmt.Errorf("archive exceeds total uncompressed byte limit")
		}
		files[name] = entry
	}
	if files["campaign-manifest.json"] == nil {
		return nil, fmt.Errorf("campaign manifest missing")
	}
	return files, nil
}

func readEntry(ctx context.Context, f *zip.File, limit int64) ([]byte, error) {
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := io.ReadAll(contextReader{ctx, io.LimitReader(r, limit+1)})
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit || uint64(len(b)) != f.UncompressedSize64 {
		return nil, fmt.Errorf("archive entry size mismatch: %s", f.Name)
	}
	return b, nil
}

type ownedPath struct {
	name string
	info os.FileInfo
}
type ownedTree struct{ paths []ownedPath }

func (o *ownedTree) remember(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	o.paths = append(o.paths, ownedPath{path, info})
	return nil
}
func (o *ownedTree) mkdir(path string) error {
	if err := privatefs.Mkdir(path); err != nil {
		return err
	}
	return o.remember(path)
}
func (o *ownedTree) create(path string) (*os.File, error) {
	f, err := privatefs.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	o.paths = append(o.paths, ownedPath{path, info})
	return f, nil
}
func (o *ownedTree) cleanup() {
	// Never recursively delete a path. Remove only unchanged identities created
	// by this invocation; a concurrent replacement or user file is preserved.
	for i := len(o.paths) - 1; i >= 0; i-- {
		p := o.paths[i]
		if privatefs.CheckPath(p.name) != nil {
			continue
		}
		current, err := os.Lstat(p.name)
		if err == nil && os.SameFile(current, p.info) {
			_ = os.Remove(p.name)
		}
	}
}
func (o *ownedTree) write(path string, data []byte) error {
	if int64(len(data)) > MaxFileBytes {
		return fmt.Errorf("generated review exceeds file limit")
	}
	f, err := o.create(path)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	return errors.Join(werr, f.Sync(), f.Close())
}

func extract(ctx context.Context, tree *ownedTree, entry *zip.File, dest string, expected File) error {
	r, err := entry.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	f, err := tree.create(dest)
	if err != nil {
		return err
	}
	h := sha256.New()
	guard := &artifactTextGuard{}
	n, copyErr := io.CopyBuffer(io.MultiWriter(f, h, guard), contextReader{ctx, io.LimitReader(r, expected.Bytes+1)}, make([]byte, 64<<10))
	if copyErr == nil {
		copyErr = guard.finish()
	}
	if copyErr == nil && (n != expected.Bytes || hex.EncodeToString(h.Sum(nil)) != expected.SHA256) {
		copyErr = fmt.Errorf("campaign integrity mismatch: %s", expected.Path)
	}
	if copyErr == nil {
		copyErr = ctx.Err()
	}
	if copyErr == nil {
		copyErr = f.Sync()
	}
	return errors.Join(copyErr, f.Close())
}

// Import extracts only the fixed campaign data schema into a new private
// directory. Invalid archives are rejected before output creation when possible;
// later failures remove only unchanged paths created by this invocation.
func Import(ctx context.Context, archivePath, outputDir string) (result Result, err error) {
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if archivePath == "" || outputDir == "" {
		return result, fmt.Errorf("archive and output are required")
	}
	if err = privatefs.CheckPath(archivePath); err != nil {
		return result, err
	}
	named, err := os.Lstat(archivePath)
	if err != nil {
		return result, err
	}
	// Reject FIFOs/devices before opening: opening a FIFO could block before a
	// context-aware reader ever gets control.
	if !named.Mode().IsRegular() {
		return result, fmt.Errorf("campaign archive must be a regular file")
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return result, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(named, info) {
		return result, fmt.Errorf("campaign archive must be a regular file")
	}
	files, err := inspectZIP(f, info.Size())
	if err != nil {
		return result, err
	}
	manifestData, err := readEntry(ctx, files["campaign-manifest.json"], MaxManifestBytes)
	if err != nil {
		return result, err
	}
	var manifest Manifest
	if err = bundle.Decode(manifestData, &manifest); err != nil {
		return result, fmt.Errorf("campaign manifest: %w", err)
	}
	if err = validateManifest(manifest); err != nil {
		return result, err
	}
	if len(files) != len(manifest.Files)+1 {
		return result, fmt.Errorf("archive file list does not exactly match campaign manifest")
	}
	for _, expected := range manifest.Files {
		entry := files[expected.Path]
		if entry == nil || entry.UncompressedSize64 != uint64(expected.Bytes) {
			return result, fmt.Errorf("manifest file missing or size mismatch: %s", expected.Path)
		}
	}
	archiveHash := sha256.New()
	if _, err = io.CopyBuffer(archiveHash, contextReader{ctx, io.NewSectionReader(f, 0, info.Size())}, make([]byte, 64<<10)); err != nil {
		return result, err
	}
	outputDir, err = filepath.Abs(outputDir)
	if err != nil {
		return result, err
	}
	if err = privatefs.CheckPath(outputDir); err != nil {
		return result, err
	}
	if _, err = os.Lstat(outputDir); err == nil {
		return result, fmt.Errorf("import output must be a new directory")
	} else if !os.IsNotExist(err) {
		return result, err
	}
	parent := filepath.Dir(outputDir)
	if _, err = os.Stat(parent); os.IsNotExist(err) {
		if err = privatefs.MkdirAll(parent); err != nil {
			return result, err
		}
	} else if err != nil {
		return result, err
	}
	tree := &ownedTree{}
	if err = tree.mkdir(outputDir); err != nil {
		return result, err
	}
	defer func() {
		if err != nil {
			tree.cleanup()
		}
	}()
	dirs := map[string]bool{outputDir: true}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	for _, expected := range manifest.Files {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		dest := filepath.Join(outputDir, filepath.FromSlash(expected.Path))
		// allowedPath uses only fixed ASCII components; containment is still
		// checked explicitly at the filesystem boundary.
		rel, e := filepath.Rel(outputDir, dest)
		if e != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return result, fmt.Errorf("archive path escaped import root")
		}
		current := outputDir
		parts := strings.Split(expected.Path, "/")
		for _, part := range parts[:len(parts)-1] {
			current = filepath.Join(current, part)
			if !dirs[current] {
				if err = tree.mkdir(current); err != nil {
					return result, err
				}
				dirs[current] = true
			}
		}
		if err = extract(ctx, tree, files[expected.Path], dest, expected); err != nil {
			return result, err
		}
	}
	if err = tree.write(filepath.Join(outputDir, "campaign-manifest.json"), manifestData); err != nil {
		return result, err
	}
	result = Result{CampaignID: manifest.CampaignID, OutputDir: outputDir, IndexPath: filepath.Join(outputDir, "index.html"), ArchiveSHA256: hex.EncodeToString(archiveHash.Sum(nil)), FileCount: len(files), Reports: []ImportedReport{}, IntegrityBoundary: "Campaign and report hashes verify retained bytes, not server authenticity, physical health, or release qualification."}
	for _, file := range manifest.Files {
		result.UncompressedBytes += file.Bytes
	}
	result.UncompressedBytes += int64(len(manifestData))
	for _, run := range []string{"quick", "standard"} {
		evidence := filepath.Join(outputDir, "runs", run, "evidence")
		if !dirs[evidence] {
			continue
		}
		if err = ctx.Err(); err != nil {
			return result, err
		}
		if err = report.Verify(evidence); err != nil {
			return result, fmt.Errorf("verify imported %s report: %w", run, err)
		}
		r, e := report.Read(filepath.Join(evidence, "report.json"))
		if e != nil {
			return result, fmt.Errorf("read imported %s report: %w", run, e)
		}
		if r.Tier != run {
			return result, fmt.Errorf("imported report tier differs from run directory")
		}
		// Render with this installed binary's escaped, CSP-restricted template.
		// Imported report.html remains preserved evidence and is never opened.
		html, e := report.HTML(r)
		if e != nil {
			return result, e
		}
		reviewDir := filepath.Join(outputDir, "review")
		if !dirs[reviewDir] {
			if err = tree.mkdir(reviewDir); err != nil {
				return result, err
			}
			dirs[reviewDir] = true
		}
		reviewPath := filepath.Join(reviewDir, run+".html")
		if err = tree.write(reviewPath, html); err != nil {
			return result, err
		}
		result.Reports = append(result.Reports, ImportedReport{Run: run, Directory: evidence, ReviewPath: reviewPath, ScanID: r.ScanID, Verdict: r.Verdict, Synthetic: r.Synthetic})
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = writeIndex(tree, result); err != nil {
		return result, err
	}
	orderedDirs := make([]string, 0, len(dirs))
	for dir := range dirs {
		orderedDirs = append(orderedDirs, dir)
	}
	sort.Slice(orderedDirs, func(i, j int) bool { return len(orderedDirs[i]) > len(orderedDirs[j]) })
	for _, dir := range orderedDirs {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		if err = privatefs.SyncDir(dir); err != nil {
			return result, err
		}
	}
	return result, nil
}
