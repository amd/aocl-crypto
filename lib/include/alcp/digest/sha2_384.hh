/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/digest.hh"
#include "sha2_512.hh"

#include <memory>

namespace alcp::digest {

class ALCP_API_EXPORT Sha384 final : public Sha2
{
  public:
    Sha384();
    Sha384(const alc_digest_info_t& rDInfo);
    virtual ~Sha384();
    alc_error_t update(const Uint8* pMsgBuf, Uint64 size) override;
    void        finish() override;
    void        reset() override;
    alc_error_t finalize(const Uint8* pMsgBuf, Uint64 size) override;
    alc_error_t copyHash(Uint8* pHashBuf, Uint64 size) const override;

    /**
     * @return The input block size to the hash function in bytes
     */
    Uint64 getInputBlockSize() override;

    /**
     * @return The digest size in bytes
     */
    Uint64 getHashSize() override;

  private:
    std::shared_ptr<Sha512> m_psha512;
};

} // namespace alcp::digest
