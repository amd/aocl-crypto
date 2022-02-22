/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#pragma once

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
