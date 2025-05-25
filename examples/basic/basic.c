#include "..\shared.h"

int main(int argc, char **argv) {
  af_byte *image = ( af_byte * ) ( GetModuleHandleA(0) );
  return __af_shared_mintegrity_routine(image);
}
