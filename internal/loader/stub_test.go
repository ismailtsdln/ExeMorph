package loader

import (
	"testing"
)

func TestGetStub(t *testing.T) {
	stub, err := GetStub("x64", 0x1000, 0x2000)
	if err != nil {
		t.Fatalf("Failed to generate stub: %v", err)
	}

	if len(stub) == 0 {
		t.Error("Generated stub is empty")
	}

	// Verify Prologue (sub rsp, 0x28)
	expectedPrologue := []byte{0x48, 0x83, 0xEC, 0x28}
	for i, b := range expectedPrologue {
		if stub[i] != b {
			t.Errorf("Byte %d mismatch: expected 0x%X, got 0x%X", i, b, stub[i])
		}
	}
}
