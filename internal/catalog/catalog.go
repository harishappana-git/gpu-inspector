// Package catalog preserves all 147 design checks, including future and opt-in
// checks so omission cannot be confused with a pass.
package catalog

import (
	_ "embed"
	"encoding/json"
	"github.com/harishappana/gpu-inspector/internal/model"
)

//go:embed checks.json
var data []byte

func All() []model.Check {
	var checks []model.Check
	if err := json.Unmarshal(data, &checks); err != nil {
		panic(err)
	}
	return checks
}

func InTier(c model.Check, tier string) bool {
	return c.Stage == "Q" || (tier == "standard" && c.Stage == "S")
}

// Decision gates concern usable scope, current correctness and qualified
// performance. Ancillary unavailable sensors still remain in the coverage table.
func Mandatory(id, tier string) bool {
	switch id {
	case "A01", "A02", "A04", "A05", "A06", "A07", "A08", "B03", "B07", "B09", "B12", "C01", "C02", "C05", "C07", "H02", "H03":
		return true
	case "B08", "B10", "C10", "C12", "J01":
		return tier == "standard"
	}
	return false
}
