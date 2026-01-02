package analysis

import (
	"debug/pe"
	"fmt"
)

// PEFile is a wrapper around the standard debug/pe.File to add helper methods
// for ExeMorph's specific needs.
type PEFile struct {
	*pe.File
	FilePath string
}

// NewPEFile opens a PE file and returns a parsed PEFile struct.
func NewPEFile(path string) (*PEFile, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open PE file: %w", err)
	}
	return &PEFile{File: f, FilePath: path}, nil
}

// Close closes the underlying PE file.
func (f *PEFile) Close() error {
	return f.File.Close()
}

// GetArch returns a string representation of the PE architecture.
func (f *PEFile) GetArch() string {
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	default:
		return fmt.Sprintf("Unknown (0x%x)", f.Machine)
	}
}

// IsDLL checks if the PE file has the DLL characteristic set.
func (f *PEFile) IsDLL() bool {
	return (f.FileHeader.Characteristics & pe.IMAGE_FILE_DLL) != 0
}
