/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

#include "Fuzz/alcp_fuzz_test.hh"

int
FuzzerTestOneInput(alc_digest_mode_t mode, const Uint8* buf, size_t len)
{
    Uint32 srcSize = len;

    /* Initializing digest info */
    alc_error_t         err;
    alc_digest_handle_p m_handle = new alc_digest_handle_t;

    Uint32 out_size = sha2_mode_len_map[mode];

    /* for non-shake variants */
    if (out_size % 8 == 0) {
        out_size = out_size / 8;
    }
    /* for shake variants */
    else if (out_size == ALC_DIGEST_LEN_CUSTOM_SHAKE_128
             || out_size == ALC_DIGEST_LEN_CUSTOM_SHAKE_256) {
        FuzzedDataProvider stream(buf, len);
        out_size = stream.ConsumeIntegral<Uint32>();
    } else {
        std::cout << sha2_mode_string_map[mode]
                  << " is not supported. Exiting.." << std::endl;
        return 0;
    }
    Uint8 output1[out_size], output2[out_size];

    /* Start to Fuzz Digest APIs */
    FuzzedDataProvider stream(buf, len);
    Uint64             context_size = alcp_digest_context_size();

    if (m_handle == nullptr) {
        std::cout << "Error: Mem alloc for digest handle" << std::endl;
        goto OUT;
    }
    /* Request a context with dinfo */
    m_handle->context = malloc(context_size);
    if (m_handle->context == nullptr) {
        std::cout << "Error: Mem alloc for digest context" << std::endl;
        goto OUT;
    }
    /*FIXME: add lifecycle changes here, and randomize the order of the calls */
    err = alcp_digest_request(mode, m_handle);
    Check_Error(err);
    err = alcp_digest_init(m_handle);
    Check_Error(err);
    err = alcp_digest_update(m_handle, buf, srcSize);
    Check_Error(err);
    err = alcp_digest_finalize(m_handle, output1, out_size);
    Check_Error(err);

    goto CLOSE;

CLOSE:
    if (m_handle != nullptr) {
        alcp_digest_finish(m_handle);
        free(m_handle->context);
        delete m_handle;
    }

OUT:
    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    int retval = 0;
    for (auto const& [Mode, Len] : sha2_mode_len_map) {
        if (FuzzerTestOneInput(Mode, Data, Size) != 0) {
            std::cout << "Digest fuzz test failed for Mode"
                      << sha2_mode_string_map[Mode] << std::endl;
            return retval;
        }
    }
    return retval;
}