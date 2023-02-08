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

#include <memory>
#include <string>

#include "alcp/base.hh"
#include "alcp/interface/Irng.hh"
#include "config.h"

namespace alcp::rng {

class Rng : public IRng
{
  protected:
    Rng()          = default;
    virtual ~Rng() = default;

    virtual void finish() = 0;

  private:
    // FIXME: Unused Variable
#if 0
bool m_initialized = false;
#endif
};

class OsRng final : public Rng
{
  public:
    OsRng() {}
    //explicit OsRng(ISeeder);
    ~OsRng() {}

  public:
    Status readRandom(Uint8* pBuf, Uint64 size) override;
    Status readUrandom(Uint8* buffer, Uint64 size);
    void   finish() override;
};

class ArchRng final : public Rng
{
  public:
    ArchRng() {}
    //explicit ArchRng(const alc_rng_info_t& rRnginfo);
    ~ArchRng() {}

    Status readRandom(Uint8* pBuf, Uint64 size) override;
    void   finish() override;
};

} // namespace alcp::rng
