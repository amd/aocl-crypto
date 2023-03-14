/*
 * Copyright (C) 2019-2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/alcp.hh"
#include "alcp/base.hh"
#include "alcp/interface/Iwriter.hh"
#include "alcp/pattern/noncopyable.hh"
#include <algorithm>

namespace alcp {

/*
 * BufferWriter:
 *  A class designed to cope with API design as to avoid
 *  reading from a write-only buffer.
 *  Unless writeAt() is used, the buffer is always will be overwritten.
 *  We dont expect IO errors/exceptions to happen here as
 *  the buffer is an in-memory sink.
 *
 *  eg :
 *
 *  void writeKey(void * const key, int length)
 *  {
 *  #define SIZE 1024
 *      uint8_t *buf = new uint8_t[SIZE];
 *      BufferWriter bw(buf, SIZE);
 *      assert(bw.write(key, length), length);
 *  }
 *
 */

class ALCP_API_EXPORT BufferWriter
    : public IWriter
    , public NonCopyable
{
    using size_t = std::size_t;

  public:
    ALCP_DEFS_DEFAULT_CTOR_AND_DTOR(BufferWriter);

    explicit BufferWriter(void* const pointer, size_t length)
        : m_ptr{ pointer }
        , m_length{ length }
    {
    }

    virtual size_t write(void const* const buffer,
                         size_t            len) const noexcept override;

    virtual size_t writeAt(void const* const buffer,
                           size_t            len,
                           size_t offset = 0) const noexcept override;

  private:
    void* const m_ptr = nullptr;
    size_t      m_length;
};

} // namespace alcp
