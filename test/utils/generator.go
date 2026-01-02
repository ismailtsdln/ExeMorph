package utils

import (
	"encoding/binary"
	"os"
)

// GenerateDummyDLL creates a minimal PE32+ (x64) DLL file at the specified path.
// It constructs just enough of the PE header to satisfy debug/pe and our parser.
func GenerateDummyDLL(path string) error {
	// Minimal PE Layout:
	// DOS Header (64 bytes)
	// PE Signature (4 bytes)
	// File Header (20 bytes)
	// Optional Header (240 bytes for x64)
	// Section Table (40 bytes * 1)
	// Section Data (Aligned)

	// Total size will be small.

	// offsets
	peHeaderOffset := 0x40 // Standard

	buf := make([]byte, 4096) // 4KB page should be enough

	// 1. DOS Header
	copy(buf[0:], []byte("MZ"))
	binary.LittleEndian.PutUint32(buf[0x3c:], uint32(peHeaderOffset))

	// 2. PE Header
	copy(buf[peHeaderOffset:], []byte("PE\x00\x00"))

	// File Header
	fhOffset := peHeaderOffset + 4
	binary.LittleEndian.PutUint16(buf[fhOffset:], 0x8664)    // Machine: x64
	binary.LittleEndian.PutUint16(buf[fhOffset+2:], 1)       // NumberOfSections: 1
	binary.LittleEndian.PutUint16(buf[fhOffset+16:], 0xF0)   // SizeOfOptionalHeader: 240
	binary.LittleEndian.PutUint16(buf[fhOffset+18:], 0x2000) // Characteristics: IMAGE_FILE_DLL

	// Optional Header
	ohOffset := fhOffset + 20
	// Magic
	binary.LittleEndian.PutUint16(buf[ohOffset:], 0x20b) // PE32+

	// Standard fields
	// AddressOfEntryPoint (offset 16)
	binary.LittleEndian.PutUint32(buf[ohOffset+16:], 0x1000) // EntryPoint RVA

	// Windows specific fields
	// ImageBase (offset 24) - 8 bytes
	binary.LittleEndian.PutUint64(buf[ohOffset+24:], 0x180000000)
	// SectionAlignment (offset 32)
	binary.LittleEndian.PutUint32(buf[ohOffset+32:], 0x1000)
	// FileAlignment (offset 36)
	binary.LittleEndian.PutUint32(buf[ohOffset+36:], 0x200)

	// SizeOfImage (offset 56)
	binary.LittleEndian.PutUint32(buf[ohOffset+56:], 0x3000) // Header + Section
	// SizeOfHeaders (offset 60)
	binary.LittleEndian.PutUint32(buf[ohOffset+60:], 0x200) // Aligned headers

	// NumberOfRvaAndSizes (offset 108 for PE32+, 92 for PE32)
	binary.LittleEndian.PutUint32(buf[ohOffset+108:], 16)

	// 3. Section Table
	stOffset := ohOffset + 240
	// Name: .text
	copy(buf[stOffset:], []byte(".text"))
	// VirtualSize
	binary.LittleEndian.PutUint32(buf[stOffset+8:], 0x1000)
	// VirtualAddress
	binary.LittleEndian.PutUint32(buf[stOffset+12:], 0x1000)
	// SizeOfRawData
	binary.LittleEndian.PutUint32(buf[stOffset+16:], 0x200)
	// PointerToRawData
	binary.LittleEndian.PutUint32(buf[stOffset+20:], 0x200)
	// Characteristics
	binary.LittleEndian.PutUint32(buf[stOffset+36:], 0x60000020)

	return os.WriteFile(path, buf, 0644)
}
