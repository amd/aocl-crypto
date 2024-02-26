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

#include "alcp/types.hh"

namespace alcp::testing::cipher {

struct alc_test_init_data_t
{
    Uint8* m_key;
    Uint32 m_key_len;

    alc_test_init_data_t()
        : m_key{ nullptr }
        , m_key_len{ 0 }
    {}
};
using alc_test_init_data_p = alc_test_init_data_t*;

struct alc_test_update_data_t
{
    const Uint8* m_input;
    Uint64       m_input_len;
    Uint8*       m_output;
    Uint64       m_output_len;

    alc_test_update_data_t()
        : m_input{ nullptr }
        , m_input_len{ 0 }
        , m_output{ nullptr }
        , m_output_len{ 0 }
    {}
};
using alc_test_update_data_p = alc_test_update_data_t*;

struct alc_test_finalize_data_t
{
    bool verified;

    alc_test_finalize_data_t()
        : verified{ false }
    {}
};
using alc_test_finalize_data_p = alc_test_finalize_data_t*;

} // namespace alcp::testing::cipher