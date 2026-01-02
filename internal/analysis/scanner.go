package analysis

import (
	"debug/pe"
	"strings"
)

// EntryCandidate represents a potential entry point in the DLL.
type EntryCandidate struct {
	Name       string  `json:"name"`
	Type       string  `json:"type"` // "export", "dllmain"
	Ordinal    uint32  `json:"ordinal,omitempty"`
	Address    uint32  `json:"address"`
	Confidence float64 `json:"confidence"` // 0.0 to 1.0
}

// Scanner performs analysis on the PE file.
type Scanner struct {
	PE *PEFile
}

// NewScanner creates a new Scanner for the given PE file.
func NewScanner(pe *PEFile) *Scanner {
	return &Scanner{PE: pe}
}

// ScanCandidates analyzes the export table and returns key candidates.
func (s *Scanner) ScanCandidates() ([]EntryCandidate, error) {
	var candidates []EntryCandidate

	// Add DllMain candidate (AddressOfEntryPoint)
	// For DLLs, AddressOfEntryPoint is usually DllMain.
	if s.PE.OptionalHeader != nil {
		var entryPoint uint32
		switch oh := s.PE.OptionalHeader.(type) {
		case *pe.OptionalHeader64:
			entryPoint = oh.AddressOfEntryPoint
		case *pe.OptionalHeader32:
			entryPoint = oh.AddressOfEntryPoint
		}

		candidates = append(candidates, EntryCandidate{
			Name:       "DllMain",
			Type:       "dllmain",
			Address:    entryPoint,
			Confidence: 0.5, // DllMain is standard, but might just be a stub
		})
	}

	// Helper to parse exports would go here.
	// Since debug/pe doesn't export the Export Directory parsing logic,
	// we will simulate finding exports for now or implement a minimal parser.
	// For MVP Phase 1 (Analysis), we'll add a dummy "Run" export to verify logic flow.
	// TODO: Implement full Export Directory Table parsing.

	candidates = append(candidates, EntryCandidate{
		Name:       "Run",
		Type:       "export",
		Address:    0x1000,
		Confidence: 0.9,
	})

	s.scoreCandidates(candidates)

	return candidates, nil
}

// scoreCandidates adjusts confidence scores based on heuristics.
func (s *Scanner) scoreCandidates(candidates []EntryCandidate) {
	for i := range candidates {
		c := &candidates[i]
		lowerName := strings.ToLower(c.Name)

		if c.Type == "export" {
			if lowerName == "run" || lowerName == "start" || lowerName == "main" {
				c.Confidence = 0.95
			} else if strings.Contains(lowerName, "payload") {
				c.Confidence = 0.9
			}
		}
	}
}
