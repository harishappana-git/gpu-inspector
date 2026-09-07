package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/harishappana/gpu-inspector/internal/campaignimport"
)

func importCommand(ctx context.Context, args []string, out, stderr io.Writer) error {
	f := flags("import", stderr)
	archive := f.String("archive", "", "downloaded data-only H100 campaign ZIP")
	dest := f.String("output", "", "new owner-private local review directory")
	jsonOutput := f.Bool("json", false, "print import result and local index_path as JSON")
	if err := parse(f, args); err != nil {
		return err
	}
	result, err := campaignimport.Import(ctx, *archive, *dest)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(out).Encode(result)
	}
	fmt.Fprintf(out, "Imported %d campaign files; verified %d report directories.\nReview: %s\n%s\n", result.FileCount, len(result.Reports), result.IndexPath, result.IntegrityBoundary)
	return nil
}
