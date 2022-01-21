#ifndef __RNG_HH
#define __RNG_HH

#include <alcp/rng.h>

namespace alcp::rng{
    int rng_engine_amd_rdrand_bytes(uint8_t * buffer,int buffersize);
    int rng_engine_linux_random(uint8_t * buffer,int buffersize);
    int rng_engine_linux_urandom(uint8_t * buffer,int buffersize);
}

#endif
