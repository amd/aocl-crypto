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
FuzzerTestOneInput(const Uint8* buf, size_t len)
{
    const Uint8* src     = buf;
    Uint32       srcSize = len;

    /* Initializing digest info */
    alc_error_t         err;
    alc_digest_handle_p m_handle = new alc_digest_handle_t;
    alc_digest_handle_p m_handle_dst =
        new alc_digest_handle_t; // For context_copy()

    // Change the digest mode here to run SHA2 and SHA3 variants
    alc_digest_mode_t mode     = ALC_SHAKE_256;
    Uint32            out_size = MODE_SIZE[mode];
    if (out_size == 0) { // For modes that are not part of MODE_SIZE
        std::cout << mode << " is not supported. Exiting.." << std::endl;
        return 0;
    } else if (out_size == 1) { // SHAKE Variants
        FuzzedDataProvider stream(buf, len);
        out_size = stream.ConsumeIntegral<Uint32>();
        // std::cout << "SHAKE: Digest_Size: " << out_size << std::endl;
    }
    Uint8 output1[out_size], output2[out_size];

    /* Start to Fuzz Digest APIs */
    FuzzedDataProvider stream(buf, len);
    Uint64 context_size = alcp_digest_context_size(); // Context_size = 96
    // std::cout << mode <<"\t" << context_size << std::endl;

    if ((m_handle == nullptr) || (m_handle_dst == nullptr)) {
        std::cout << "Error: Mem alloc for digest handle" << std::endl;
        // goto OUT;
    }
    /* Request a context with dinfo */
    m_handle->context     = malloc(context_size);
    m_handle_dst->context = malloc(context_size); // For context_copy()
    if ((m_handle->context == nullptr) || (m_handle_dst->context == nullptr)) {
        std::cout << "Error: Mem alloc for digest context" << std::endl;
        goto OUT;
    }

    /* 1. Call context_copy without request() and init()   */
    //    err = alcp_digest_context_copy(m_handle, m_handle_dst);
    //    Check_Error(err);
    /* END 1. Call context_copy without request() and init()   */

    /* 2. Call update without init()   */
    //    err = alcp_digest_request(mode, m_handle);
    //    Check_Error(err);

    //    err = alcp_digest_update(m_handle, src, srcSize);
    //    Check_Error(err);
    /* END 2. Call update without init()   */

    /* 3. Call shake_squeeze()   */
    err = alcp_digest_request(mode, m_handle);
    Check_Error(err);

    err = alcp_digest_init(m_handle);
    Check_Error(err);

    err = alcp_digest_update(m_handle, src, srcSize);
    Check_Error(err);
    err = alcp_digest_context_copy(m_handle, m_handle_dst);

    err = alcp_digest_finalize(m_handle, output1, out_size);
    Check_Error(err);

    err = alcp_digest_shake_squeeze(m_handle_dst, output2, out_size);
    Check_Error(err);

    for (int i = 0; i < out_size; i++) {
        if (output1[i] != output2[i]) {
            std::cout << "Outputs are NOT equal" << std::endl;
            break;
        }
    }
    goto CLOSE;
    /* END 3. Call shake_squeeze()   */

CLOSE:
    if (m_handle != nullptr) {
        alcp_digest_finish(m_handle);
        free(m_handle->context);
        delete m_handle;
    }
    if (m_handle_dst != nullptr) {
        alcp_digest_finish(m_handle_dst);
        free(m_handle_dst->context);
        delete m_handle_dst;
    }

OUT:
    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    return FuzzerTestOneInput(Data, Size);
}