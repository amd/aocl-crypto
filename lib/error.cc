/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
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
#include "alcp/error.h"
#include "alcp/macros.h"

#include <cstdio>

#include "error.hh"

namespace alcp {

#define ERROR_DETAIL_SHIFT  0
#define ERROR_DETAIL_LEN    16
#define ERROR_GENERAL_SHIFT (ERROR_DETAIL_SHIFT + ERROR_DETAIL_LEN)
#define ERROR_GENERAL_LEN   16
#define ERROR_MODULE_SHIFT  (ERROR_GENERAL_SHIFT + ERROR_GENERAL_LEN)
#define ERROR_MODULE_LEN    16
#define ERROR_RESERVED_LEN                                                     \
    (64 - (ERROR_MODULE_LEN + ERROR_GENERAL_LEN + ERROR_DETAIL_LEN))

static inline uint64_t
__alc_extract64(uint64_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 64 - start);
    return (value >> start) & (~0U >> (64 - length));
}

#define ALC_ERROR_DETAIL(x)                                                    \
    __alc_extract64(x.e_val, ERROR_DETAIL_SHIFT, ERROR_DETAIL_LEN)
#define ALC_ERROR_GENERAL(x)                                                   \
    __alc_extract64(x.e_val, ERROR_GENERAL_SHIFT, ERROR_GENERAL_LEN)
#define ALC_ERROR_MODULE(x)                                                    \
    __alc_extract64(x.e_val, ERROR_MODULE_SHIFT, ERROR_MODULE_LEN)

class Impl
{
  public:
    union
    {
        uint64_t value;

        struct
        {
            uint64_t module : ERROR_MODULE_LEN;     /* Module ID */
            uint64_t general : ERROR_GENERAL_LEN;   /* High level error code */
            uint64_t detail : ERROR_DETAIL_LEN;     /* Low level error code */
            uint64_t reserved : ERROR_RESERVED_LEN; /* Unused, for now */
        } fields;
    } m_data;
};

Error::Error()
//    : impl(new Impl)
{}

int
Error::print(alc_error_t& err, uint8_t* buf, uint64_t size)
{
    return std::snprintf((char*)buf, size, "An Error Occurred");
}

void
Error::setGeneric(alc_error_t& err, alc_error_generic_t gen)
{
    Impl e;
    e.m_data.value          = err;
    e.m_data.fields.general = gen;

    err = e.m_data.value;
}

void
Error::setDetail(alc_error_t& err, alc_error_generic_t det)
{
    Impl e;
    e.m_data.value         = err;
    e.m_data.fields.detail = det;

    err = e.m_data.value;
}

void
Error::setModule(alc_error_t& err, uint16_t mod)
{}

} // namespace alcp
