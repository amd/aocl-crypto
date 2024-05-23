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
ALCP_Fuzz_Digest(alc_digest_mode_t mode, const Uint8* buf, size_t len)
{
    FuzzedDataProvider stream(buf, len);

    size_t size_input = stream.ConsumeIntegralInRange<Uint16>(1, 1024);
    std::vector<Uint8> fuzz_input = stream.ConsumeBytes<Uint8>(size_input);

    /* Initializing digest info */
    alc_error_t         err;
    alc_digest_handle_p m_handle     = new alc_digest_handle_t;
    alc_digest_handle_p m_handle_dup = new alc_digest_handle_t;

    Uint32 out_size = sha_mode_len_map[mode];

    /* for non-shake variants */
    if (out_size % 8 == 0) {
        out_size = out_size / 8;
    }
    /* for shake variants */
    else if (out_size == ALC_DIGEST_LEN_CUSTOM_SHAKE_128
             || out_size == ALC_DIGEST_LEN_CUSTOM_SHAKE_256) {
        out_size = stream.ConsumeIntegral<Uint32>();
    } else {
        std::cout << sha_mode_len_map[mode] << " is not supported. Exiting.."
                  << std::endl;
        return 0;
    }

    /* output2 is to store digest data from duplicate handle */
    Uint8 output1[out_size], output2[out_size];

    Uint64 context_size = alcp_digest_context_size();

    if (m_handle == nullptr || m_handle_dup == nullptr) {
        std::cout << "Error: Mem alloc for digest handle" << std::endl;
        goto OUT;
    }

    m_handle->context     = malloc(context_size);
    m_handle_dup->context = malloc(context_size);
    if (m_handle->context == nullptr || m_handle_dup->context == nullptr) {
        std::cout << "Error: Mem alloc for digest context" << std::endl;
        goto OUT;
    }

    std::cout << "Running for Input size:" << size_input << std::endl;
    /*FIXME: add lifecycle changes here, and randomize the order of the calls */
    err = alcp_digest_request(mode, m_handle);
    Check_Error(err);
    err = alcp_digest_init(m_handle);
    Check_Error(err);
    err = alcp_digest_update(m_handle, &fuzz_input[0], fuzz_input.size());
    Check_Error(err);
    /* context copy */
    err = alcp_digest_context_copy(m_handle, m_handle_dup);
    Check_Error(err);
    /* for shake variants */
    if (sha_mode_string_map[mode].find("SHAKE") != std::string::npos) {
        err = alcp_digest_shake_squeeze(m_handle_dup, output2, out_size);
        Check_Error(err);
    }
    err = alcp_digest_finalize(m_handle, output1, out_size);
    Check_Error(err);

    if (sha_mode_string_map[mode].find("SHAKE") != std::string::npos) {
        for (int i = 0; i < out_size; i++) {
            if (output1[i] != output2[i]) {
                std::cout << "Outputs are NOT equal" << std::endl;
                break;
            }
        }
    }
    std::cout << "Passed " << sha_mode_len_map[mode]
              << " for Input size:" << size_input << std::endl;
    goto CLOSE;

CLOSE:
    if (m_handle != nullptr) {
        alcp_digest_finish(m_handle);
        free(m_handle->context);
        delete m_handle;
    }
    if (m_handle_dup != nullptr) {
        alcp_digest_finish(m_handle_dup);
        free(m_handle_dup->context);
        delete m_handle_dup;
    }

OUT:
    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    int retval = 0;
    for (auto const& [Mode, Len] : sha_mode_len_map) {
        if (ALCP_Fuzz_Digest(Mode, Data, Size) != 0) {
            std::cout << "Digest fuzz test failed for Mode"
                      << sha_mode_len_map[Mode] << std::endl;
            return retval;
        }
    }
    return retval;
}