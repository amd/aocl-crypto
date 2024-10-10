/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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
 */

#include "alcp/base/status.hh"
#include "alcp/base/error.hh"

namespace alcp::base { namespace status {
    Status AlreadyExists(const StringView msg)
    {
        auto e = GenericError{ ErrorCode::eExists };
        return Status(e, msg);
    }

    Status InvalidArgument(const StringView msg)
    {
        auto e = GenericError{ ErrorCode::eInvalidArgument };
        return Status(e, msg);
    }

    Status NotFound(const StringView msg)
    {
        auto e = GenericError{ ErrorCode::eNotFound };
        return Status(e, msg);
    }

    Status NotAvailable(const StringView msg)
    {
        auto e = GenericError{ ErrorCode::eNotAvailable };
        return Status(e, msg);
    }

    Status NotImplemented(const StringView msg)
    {
        auto e = GenericError{ ErrorCode::eNotImplemented };
        return Status(e, msg);
    }

    Status Unknown(const StringView msg)
    {
        auto e = GenericError{ ErrorCode::eUnknown };
        return Status(e, msg);
    }

    Status InternalError(const StringView sv)
    {
        auto e = GenericError{ ErrorCode::eInternal };
        return Status(e, sv);
    }
}} // namespace alcp::base::status
