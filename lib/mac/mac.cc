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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "mac/mac.hh"
#include <iostream>
namespace alcp::mac {

class alignas(16) Mac::Impl
{
  private:
    std::shared_ptr<Uint8[]> m_key;
    Uint64                   m_keylen;

  public:
    alc_error_t setUp(const alc_key_info_t& rKeyInfo)
    {
        // For RAW assignments
        switch (rKeyInfo.fmt) {

            case ALC_KEY_FMT_RAW:
                m_keylen = rKeyInfo.len;
                m_key    = std::make_shared<Uint8[]>(m_keylen);
                break;
            case ALC_KEY_FMT_BASE64:
                // TODO: For base64 conversions
                return ALC_ERROR_NOT_SUPPORTED; // remove this return when above
                                                // todo is resolved.
                break;
            // TODO: Subsequest switch cases for other formats
            default:
                return ALC_ERROR_NOT_SUPPORTED;
        }
        return ALC_ERROR_NONE;
    }
};

Mac::Mac()
    : m_pimpl{ std::make_unique<Mac::Impl>() }
{}

Mac::Mac(const alc_key_info_t& rKeyInfo)
    : Mac{}
{
    m_pimpl->setUp(rKeyInfo);
}

Mac::~Mac() {}

} // namespace alcp::mac