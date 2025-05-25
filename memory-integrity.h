#ifndef __AF_MINTEGRITY_H__
#define __AF_MINTEGRITY_H__

#include <windows.h>
#include <winnt.h>

#ifdef _MSC_VER
  #include <immintrin.h>
#endif

/* -- macros ------------------------------------------ */
#ifdef _MSC_VER
  #define _af_mintegrity_api __forceinline
#else
  #define _af_mintegrity_api __attribute__((always_inline))
#endif

/* -- forward winnt types ----------------------------- */
typedef IMAGE_DOS_HEADER     _af_win_image_dos_header;
typedef IMAGE_NT_HEADERS     _af_win_image_nt_headers;
typedef IMAGE_FILE_HEADER    _af_win_image_file_header;
typedef IMAGE_SECTION_HEADER _af_win_image_section_header;

/* -- af types ---------------------------------------- */
typedef unsigned char      af_byte;
typedef unsigned short     af_word;
typedef unsigned int       af_dword;
typedef unsigned long long af_qword;
typedef unsigned long      af_status;

/* -- af statuses ------------------------------------- */
#define AF_MINTEGRITY_SUCCESS       ( 1 << 0 )
#define AF_MINTEGRITY_INVALID_IMAGE ( 1 << 1 )

/* -- af structs -------------------------------------- */
typedef struct af_mintegrity_s {
  af_byte *image;
  af_dword checksum;
} af_mintegrity_t;

/* -- forward checksum fn declare --------------------- */
void af_mintegrity_checksum(const af_byte *const, af_dword, af_dword *);

#ifndef AF_MINTEGRITY_CHECKSUM_INITIAL
#define AF_MINTEGRITY_CHECKSUM_INITIAL ( 0ULL )
#endif

#ifndef AF_MINTEGRITY_CUSTOM_CHECKSUM
/*
 * Computes a CRC32 checksum over a byte array using hardware-accelerated
 * instructions. Requires CRC32 instruction support (-mcrc32 flag for GCC/Clang).
 */
_af_mintegrity_api void af_mintegrity_checksum(const af_byte *const data, af_dword length, af_dword *checksum) {
  af_dword index = 0;
  for ( ; index < length; index++ ) {
#ifdef _MSC_VER
    *checksum = _mm_crc32_u8(*checksum, data[index]);
#else
    *checksum = __builtin_ia32_crc32qi(*checksum, data[index]);
#endif
  }
}
#endif

/*
 * Parses a Windows Portable Executable (PE) image and
 * computes a cumulative checksum for non-writable sections.
 */
_af_mintegrity_api af_status __af_mintegrity_section_checksum(af_byte *image, af_dword *checksum) {
  _af_win_image_dos_header *dos = ( _af_win_image_dos_header * ) ( image );
  if ( dos->e_magic != IMAGE_DOS_SIGNATURE ) {
    return AF_MINTEGRITY_INVALID_IMAGE;
  }

  _af_win_image_nt_headers  *nt = ( _af_win_image_nt_headers * ) ( image + dos->e_lfanew );
  _af_win_image_file_header *fh = &nt->FileHeader;

  _af_win_image_section_header *start = IMAGE_FIRST_SECTION(nt);
  _af_win_image_section_header *end   = start + fh->NumberOfSections;
  while ( start < end ) {
    _af_win_image_section_header *section = start++;
    if ( section->Characteristics & IMAGE_SCN_MEM_WRITE ) {
      continue;
    }

    af_byte *scdata = image + section->VirtualAddress;
    af_dword length = section->Misc.VirtualSize;
    af_mintegrity_checksum(scdata, length, checksum);
  }

  return AF_MINTEGRITY_SUCCESS;
}

/*
 * Initializes a memory integrity context with a PE image and computes baseline checksum.
 */
_af_mintegrity_api af_status af_mintegrity_initialize(af_mintegrity_t *integrity, af_byte *image) {
  integrity->image = image;
  integrity->checksum = AF_MINTEGRITY_CHECKSUM_INITIAL;
  return __af_mintegrity_section_checksum(image, &integrity->checksum);
}

/*
 * Performs runtime memory integrity verification by computing a new checksum of
 * the PE image's non-writable sections and comparing it to the baseline checksum.
 */
_af_mintegrity_api af_byte af_mintegrity_compare(af_mintegrity_t *integrity, af_dword *checksum) {
  *checksum = AF_MINTEGRITY_CHECKSUM_INITIAL;
  __af_mintegrity_section_checksum(integrity->image, checksum);
  return integrity->checksum == *checksum;
}

#endif
