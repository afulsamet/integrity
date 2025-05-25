#define AF_MINTEGRITY_CUSTOM_CHECKSUM
#define AF_MINTEGRITY_CHECKSUM_INITIAL ( 0x811C9DC5 ) /* FNV_offset_basis */
#include "..\shared.h"

/*
 * FNV1a 32-bit implementation
 * https://en.m.wikipedia.org/wiki/Fowler–Noll–Vo_hash_function
 */
_af_mintegrity_api void af_mintegrity_checksum(const af_byte *const data, af_dword length, af_dword *checksum) {
  af_dword index = 0;
  for ( ; index < length; ++index ) {
    *checksum ^= data[index];
    *checksum *= 0x01000193; /* FNV_prime */
  }
}

int main(int argc, char **argv) {
  af_byte *image = ( af_byte * ) ( GetModuleHandleA(0) );
  return __af_shared_mintegrity_routine(image);
}
