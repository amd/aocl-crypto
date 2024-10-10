/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#include "cipher_experimental/cipher_data.hh"

namespace alcp::testing::cipher::xts {

// Tweak Key is appended with key itself.
struct alc_test_xts_init_data_t : public alc_test_init_data_t
{
    Uint8* m_iv;
    Uint64 m_iv_len;
    alc_test_xts_init_data_t()
        : alc_test_init_data_t()
        , m_iv{ nullptr }
        , m_iv_len{ 0 }
    {
    }
};
using alc_test_xts_init_data_p = alc_test_xts_init_data_t*;

struct alc_test_xts_update_data_t : public alc_test_update_data_t
{
    Uint8* m_iv;
    Uint64 m_iv_len;
    Uint64 m_aes_block_id;
    Uint64 m_total_input_len;
    alc_test_xts_update_data_t()
        : alc_test_update_data_t()
        , m_iv{ nullptr }
        , m_iv_len{ 0 }
        , m_aes_block_id{ 0 }
        , m_total_input_len{ 0 }
    {
    }
};
using alc_test_xts_update_data_p = alc_test_xts_update_data_t*;

struct alc_test_xts_finalize_data_t : public alc_test_finalize_data_t
{
    Uint8* m_out;
    Uint64 m_pt_len; // Plain Text Length
    alc_test_xts_finalize_data_t()
        : alc_test_finalize_data_t()
        , m_out{ nullptr }
        , m_pt_len{ 0 }
    {
    }
};
using alc_test_xts_finalize_data_p = alc_test_xts_finalize_data_t*;

} // namespace alcp::testing::cipher::xts