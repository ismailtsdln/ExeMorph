package transform

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/ismailtsdln/ExeMorph/internal/loader"
)

// BuildOptions contains configuration for the build process.
type BuildOptions struct {
	EntryExport string
	OutputFile  string
}

// Transform converts a DLL to an EXE.
func Transform(srcPath string, opts BuildOptions) error {
	// 1. Read the source file
	raw, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	// 2. Parse PE to get offsets (we need a reader for debug/pe)
	f, err := pe.NewFile(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("failed to parse PE: %w", err)
	}
	defer f.Close()

	// 3. Convert DLL Characteristics -> EXE
	// IMAGE_FILE_DLL = 0x2000. We need to clear this bit.
	// Offset logic: DOS Header (64) + PE Sig (4) + FileHeader (20) -> Characteristics is at offset 18 in FileHeader.
	// Standard PE header offset is at 0x3C in DOS header.

	peHeaderOffset := int64(binary.LittleEndian.Uint32(raw[0x3c:]))
	// Characteristics is at PE Header + 4 (Sig) + 18 (Field offset in FileHeader)
	charOffset := peHeaderOffset + 4 + 18

	characteristics := binary.LittleEndian.Uint16(raw[charOffset:])
	if characteristics&0x2000 != 0 {
		fmt.Println("[Transform] Removing DLL characteristic flag...")
		characteristics &^= 0x2000 // Clear bit
		binary.LittleEndian.PutUint16(raw[charOffset:], characteristics)
	}

	// 4. Generate Loader Stub
	// For now, we use placeholders for offsets
	stub, err := loader.GetStub("x64", 0, 0)
	if err != nil {
		return fmt.Errorf("failed to generate stub: %w", err)
	}

	// 5. Inject Stub
	// Strategy: Append a new section ".morph" containing the stub.
	// This requires:
	// - Updating NumberOfSections
	// - Adding a Section Header
	// - Appending data
	// - Updating SizeOfImage

	// WARNING: Proper section appending is complex (alignment, header space).
	// For this prototype, if we cannot safely append, we might fail or produce a risky binary.
	// We will implement a simplified append assuming there is space for the header.

	// Check space for new section header
	// SizeOfOptionalHeader
	optHeaderSize := binary.LittleEndian.Uint16(raw[peHeaderOffset+4+16:])
	sectionTableOffset := peHeaderOffset + 4 + 20 + int64(optHeaderSize)

	numSectionsOffset := peHeaderOffset + 4 + 2
	numSections := binary.LittleEndian.Uint16(raw[numSectionsOffset:])

	// Calculate where the new header would go
	currentTableEnd := sectionTableOffset + int64(numSections)*40 // 40 bytes per section header

	// Ideally we check if currentTableEnd + 40 overlaps with the first section's data.
	// For now, we trust there is standard padding (typically there is).

	fmt.Printf("[Transform] Appending new section '.morph' at offset 0x%x\n", currentTableEnd)

	// Construct Section Header (40 bytes)
	// Name (8), VirtualSize(4), VirtualAddress(4), SizeOfRawData(4), PointerToRawData(4), ...
	newSectionHeader := make([]byte, 40)
	copy(newSectionHeader[0:], []byte(".morph"))

	// Virtual Logic:
	// We need to find the last section to calculate next RVA.
	lastSection := f.Sections[numSections-1]
	// Align text: SectionAlignment is usually 0x1000
	sectionAlignment := uint32(0x1000) // Default for 64-bit usually
	if opt64, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		sectionAlignment = opt64.SectionAlignment
	}

	nextRVA := align(lastSection.VirtualAddress+lastSection.VirtualSize, sectionAlignment)

	// Raw Logic:
	// FileAlignment usually 0x200
	fileAlignment := uint32(0x200)
	if opt64, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		fileAlignment = opt64.FileAlignment
	}

	// Raw pointer is simply end of file aligned (or just end of file if we append)
	rawEnd := uint32(len(raw))
	alignedRawPtr := align(rawEnd, fileAlignment)

	// Fill Header
	binary.LittleEndian.PutUint32(newSectionHeader[8:], uint32(len(stub)))                        // VirtualSize
	binary.LittleEndian.PutUint32(newSectionHeader[12:], nextRVA)                                 // VirtualAddress
	binary.LittleEndian.PutUint32(newSectionHeader[16:], align(uint32(len(stub)), fileAlignment)) // SizeOfRawData
	binary.LittleEndian.PutUint32(newSectionHeader[20:], alignedRawPtr)                           // PointerToRawData
	// Characteristics: CODE | EXECUTE | READ (0x60000020)
	binary.LittleEndian.PutUint32(newSectionHeader[36:], 0x60000020)

	// Write Header
	// We need to insert this header at currentTableEnd.
	// But first, verify we aren't overwriting data (SizeOfHeaders).
	sizeOfHeadersOffset := peHeaderOffset + 4 + 20 + 60 // SizeOfHeaders is at offset 60 in OptionalHeader (Standard)
	sizeOfHeaders := binary.LittleEndian.Uint32(raw[sizeOfHeadersOffset:])

	if uint32(currentTableEnd)+40 > sizeOfHeaders {
		return fmt.Errorf("not enough space for new section header")
	}

	// Write the header
	copy(raw[currentTableEnd:], newSectionHeader)

	// Update NumberOfSections
	binary.LittleEndian.PutUint16(raw[numSectionsOffset:], numSections+1)

	// Update SizeOfImage
	// SizeOfImage in Optional Header (offset 56)
	sizeOfImageOffset := peHeaderOffset + 4 + 20 + 56
	// New size = End of new section RVA
	newSizeOfImage := align(nextRVA+uint32(len(stub)), sectionAlignment)
	binary.LittleEndian.PutUint32(raw[sizeOfImageOffset:], newSizeOfImage)

	// 6. Append Stub Data
	// Pad file to alignedRawPtr
	padding := int(alignedRawPtr) - len(raw)
	if padding > 0 {
		raw = append(raw, make([]byte, padding)...)
	}
	// Append stub
	raw = append(raw, stub...)
	// Pad stub to file alignment
	finalPadding := int(align(uint32(len(stub)), fileAlignment)) - len(stub)
	if finalPadding > 0 {
		raw = append(raw, make([]byte, finalPadding)...)
	}

	// 7. Update Entry Point
	// AddressOfEntryPoint is at offset 16 in OptionalHeader64 (Standard 24 bytes file header + 4 bytes sig + 16) -> Wait.
	// PE32+ Optional Header:
	// Magic (2) + Linker (2) + CodeSize (4) + InitData (4) + UninitData (4) = 16 bytes.
	// AddressOfEntryPoint is next (4 bytes). So offset 16.
	entryPointFieldOffset := peHeaderOffset + 4 + 20 + 16
	fmt.Printf("[Transform] Updating EntryPoint: Old=0x%x -> New=0x%x\n", binary.LittleEndian.Uint32(raw[entryPointFieldOffset:]), nextRVA)
	binary.LittleEndian.PutUint32(raw[entryPointFieldOffset:], nextRVA)

	// 8. Write Output
	if err := os.WriteFile(opts.OutputFile, raw, 0755); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("[Success] Built %s\n", opts.OutputFile)
	return nil
}

func align(val, align uint32) uint32 {
	if val%align == 0 {
		return val
	}
	return val + (align - (val % align))
}
