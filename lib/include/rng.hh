#ifndef __RNG_HH
#define __RNG_HH

#include <alcp/rng.h>
#include <stdio.h>

namespace alcp {
class Rng
{
  public:
    virtual int engineDefault(uint8_t* buffer, int buffersize) = 0;
};
typedef struct
{
    void*          m_rng;
    alc_rng_info_t rng_info;
    alc_error_t (*read_random)(void* pRng, uint8_t* buffer, int buffersize);
} rng_Handle;
} // namespace alcp
namespace alcp::rng {

class OsRng : public Rng
{
  protected:
    int randomRead(uint8_t* buffer, int buffersize);
    int urandomRead(uint8_t* buffer, int buffersize);

  public:
    int engineDefault(uint8_t* buffer, int buffersize);
};

class ArchRng : public Rng
{
  protected:
    int rdRandReadBytes(uint8_t* buffer, int buffersize);

  public:
    int engineDefault(uint8_t* buffer, int buffersize);
};

namespace RngBuilder {
    alc_error_t Build(const alc_rng_info_t* tt, rng_Handle* ctx);
}
} // namespace alcp::rng

#endif