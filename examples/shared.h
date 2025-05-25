/* Standart C */
#include <stdio.h>

/* Memory integrity */
#include "..\memory-integrity.h"

_af_mintegrity_api int __af_shared_mintegrity_routine(af_byte *image) {
  af_mintegrity_t integrity;
  af_status status = af_mintegrity_initialize(&integrity, image);
  if ( status > AF_MINTEGRITY_SUCCESS ) {
    fprintf(stderr, "Failed to initialize memory integrity check. "
      "( status: %lX, image: %p )\n", status, image);
    return EXIT_FAILURE;
  }

  printf("Initialized memory integrity check with checksum %X\n", integrity.checksum);

  af_dword checksum;
  while ( af_mintegrity_compare(&integrity, &checksum) ) {
    Sleep(500);
  }

  printf("Routine is aborted because of current checksum %X\n", checksum);
  return EXIT_FAILURE;
}
