# Memory Integrity

Zero-overhead, header-only C library for runtime memory integrity verification of Windows Portable Executable (PE) images. This library provides hardware-accelerated checksum computation and real-time detection of unauthorized code modifications in non-writable sections.

## API Reference

### Initialization

```c
af_status af_mintegrity_initialize(af_mintegrity_t *integrity, af_byte *image);
```

Initializes the integrity verification context with the specified PE image and computes the baseline checksum of all non-writable sections.

**Parameters:**
- `integrity`: Pointer to integrity context structure
- `image`: Base address of the PE image

**Returns:** Status code indicating success (`AF_MINTEGRITY_SUCCESS`) or failure (`AF_MINTEGRITY_INVALID_IMAGE`)

### Verification

```c
af_byte af_mintegrity_compare(af_mintegrity_t *integrity, af_dword *checksum);
```

Performs runtime integrity verification by recomputing checksums and comparing to the baseline.

**Parameters:**
- `integrity`: Pointer to integrity context structure
- `checksum`: Current checksum value

**Returns:** Boolean result indicating integrity status (1 = intact, 0 = compromised)

### Checksum

```c
void af_mintegrity_checksum(const af_byte *const data, af_dword length, af_dword *checksum);
```

Computes hardware-accelerated CRC32 checksum over the specified byte array. This function can be overridden by defining `AF_MINTEGRITY_CUSTOM_CHECKSUM`.

## Requirements

### Compiler support
- **Microsoft Visual C++**
- **GCC/Clang**: Requires `-mcrc32` compilation flag for hardware acceleration

### Dependencies
- Windows SDK (for PE structure definitions)
- CPU with SSE4.2 support (for hardware-accelerated checksums)

## Build examples
Available toolchains are `msvc`, `gcc` and `clang`.
```bash
examples\compile-example.bat (msvc|gcc|clang) (basic|custom|image-from-peb)
```

## Contributing

- Cross-platform support extensions
- Security enhancement proposals
