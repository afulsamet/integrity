#include "..\shared.h"

af_qword af_mintegrity_rdgsq(af_qword offset) {
  af_qword reg;
#ifdef _MSC_VER
  reg = __readgsqword(offset);
#else
  __asm__ volatile ( "movq %%gs:%1, %0" : "=r" ( reg ) : "m" ( * ( af_qword * ) offset ) : "memory" );
#endif
  return reg;
}

af_byte *af_mintegrity_image(af_dword checksum) {
  af_byte *peb   =   ( af_byte *  ) ( af_mintegrity_rdgsq(0x60) );
  af_byte *head  = * ( af_byte ** ) ( peb + 0x18 ) + 0x10;
  af_byte *entry = * ( af_byte ** ) ( head );
  if ( checksum == 0 ) {
    return * ( af_byte ** ) ( entry + 0x30 );
  }

  for ( ; entry != head; entry = * ( af_byte ** ) entry ) {
    af_word *name  = * ( af_word ** ) ( entry + 0x60 );
    af_word length = * ( af_word *  ) ( entry + 0x58 ); /* in bytes */

    af_dword entry_checksum = AF_MINTEGRITY_CHECKSUM_INITIAL;
    af_mintegrity_checksum(( const af_byte *const ) name, length, &entry_checksum);
    if ( entry_checksum == checksum ) {
      return * ( af_byte ** ) ( entry + 0x30 );
    }
  }

  return 0;
}

int main(int argc, char **argv) {
  af_byte *image = af_mintegrity_image(0x404D51B3); /* crc32-checksum: ntdll.dll */
  return __af_shared_mintegrity_routine(image);
}
