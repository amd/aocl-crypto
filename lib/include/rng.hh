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
    alc_rng_info_t rng_info;
    Rng*           exec;
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
} // namespace alcp::rng

#endif