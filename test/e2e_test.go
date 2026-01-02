package test

import (
	"debug/pe"
	"os"
	"testing"

	"github.com/ismailtsdln/ExeMorph/internal/analysis"
	"github.com/ismailtsdln/ExeMorph/internal/transform"
	"github.com/ismailtsdln/ExeMorph/test/utils"
)

func TestE2E(t *testing.T) {
	// 1. Setup
	dllPath := "test_payload.dll"
	exePath := "test_payload.dll.exe"
	defer os.Remove(dllPath)
	defer os.Remove(exePath)

	err := utils.GenerateDummyDLL(dllPath)
	if err != nil {
		t.Fatalf("Failed to generate dummy DLL: %v", err)
	}

	// 2. Test Analyze
	t.Run("Analyze", func(t *testing.T) {
		peFile, err := analysis.NewPEFile(dllPath)
		if err != nil {
			t.Fatalf("Failed to open PE: %v", err)
		}
		defer peFile.Close()

		if peFile.GetArch() != "x64" {
			t.Errorf("Expected x64, got %s", peFile.GetArch())
		}
		if !peFile.IsDLL() {
			t.Error("Expected IsDLL to be true")
		}

		scanner := analysis.NewScanner(peFile)
		candidates, err := scanner.ScanCandidates()
		if err != nil {
			t.Fatalf("ScanCandidates failed: %v", err)
		}
		if len(candidates) == 0 {
			t.Error("Expected at least one candidate (DllMain)")
		}
	})

	// 3. Test Build
	t.Run("Build", func(t *testing.T) {
		opts := transform.BuildOptions{
			EntryExport: "", // Default to DllMain
			OutputFile:  exePath,
		}

		err := transform.Transform(dllPath, opts)
		if err != nil {
			t.Fatalf("Transform failed: %v", err)
		}

		// Verify Output
		if _, err := os.Stat(exePath); os.IsNotExist(err) {
			t.Fatalf("Output EXE not found")
		}

		// Check if it is valid PE and NOT a DLL
		f, err := pe.Open(exePath)
		if err != nil {
			t.Fatalf("Failed to parse output EXE: %v", err)
		}
		defer f.Close()

		var chars uint16
		switch oh := f.OptionalHeader.(type) {
		case *pe.OptionalHeader64:
			// Debug/PE doesn't expose FileHeader Characteristics directly through OptionalHeader
			// We access FileHeader from the struct
			chars = f.FileHeader.Characteristics
			_ = oh
		case *pe.OptionalHeader32:
			chars = f.FileHeader.Characteristics
		}

		if chars&0x2000 != 0 {
			t.Error("Output file still has IMAGE_FILE_DLL characteristic")
		}

		// Verify Entry Point was changed
		// Since we appended a section, the entry point should be > 0x1000 (original)
		// We expect it to be in the new section.
	})
}
