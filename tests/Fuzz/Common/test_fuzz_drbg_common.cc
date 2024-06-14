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

alc_digest_info_t rng_dinfo = {
    .dt_type = ALC_DIGEST_TYPE_SHA2,
    .dt_len  = ALC_DIGEST_LEN_256,
    .dt_mode = ALC_SHA2_256,
};

int
ALCP_Fuzz_Drbg(_alc_drbg_type DrbgType, const Uint8* buf, size_t len)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);
    size_t             size_output = stream.ConsumeIntegral<Uint16>();
    Uint8              output[size_output];
    size_t             size_max_entropy_len = stream.ConsumeIntegral<Uint16>();
    size_t             size_max_nonce_len   = stream.ConsumeIntegral<Uint16>();
    std::vector<Uint8> fuzz_custom_entropy =
        stream.ConsumeBytes<Uint8>(size_max_entropy_len);
    std::vector<Uint8> fuzz_custom_nonce =
        stream.ConsumeBytes<Uint8>(size_max_entropy_len);

    /* FIXME: add other digest modes */
    alc_drbg_handle_t handle;
    alc_drbg_info_t   drbg_info{};

    drbg_info.di_type = DrbgType;
    if (DrbgType == ALC_DRBG_HMAC) {
        drbg_info.di_algoinfo = { .hmac_drbg = { .digest_info = rng_dinfo } };
    } else if (DrbgType == ALC_DRBG_CTR) {
        drbg_info.di_algoinfo = {
            .ctr_drbg = { .di_keysize = 128, .use_derivation_function = true }
        };
    } else {
        std::cout << "Unsupported DRBG type!" << std::endl;
        return -1;
    }
    drbg_info.di_rng_sourceinfo = { .custom_rng    = true,
                                    .di_sourceinfo = {
                                        .custom_rng_info = {
                                            .entropy = &fuzz_custom_entropy[0],
                                            .entropylen = size_max_entropy_len,
                                            .nonce      = &fuzz_custom_nonce[0],
                                            .noncelen =
                                                size_max_nonce_len } } };
    drbg_info.max_entropy_len   = size_max_entropy_len;
    drbg_info.max_nonce_len     = size_max_nonce_len;

    const int cSecurityStrength = 100;

    /* Start test */
    std::cout << "Generating for output size: " << size_output
              << " Entropy len " << size_max_entropy_len << " Nonce len "
              << size_max_nonce_len << std::endl;

    err = alcp_drbg_supported(&drbg_info);
    if (alcp_is_error(err)) {
        std::cout << "Error alcp_drbg_supported" << std::endl;
        return -1;
    }

    handle.ch_context = malloc(alcp_drbg_context_size(&drbg_info));
    if (handle.ch_context == nullptr) {
        std::cout << "Error alcp_drbg_context_size" << std::endl;
        return -1;
    }
    err = alcp_drbg_request(&handle, &drbg_info);
    if (alcp_is_error(err)) {
        std::cout << "Error alcp_drbg_request" << std::endl;
        goto dealloc_exit;
    }
    err = alcp_drbg_initialize(&handle, cSecurityStrength, NULL, 0);
    if (alcp_is_error(err)) {
        std::cout << "Error alcp_drbg_initialize" << std::endl;
        goto dealloc_exit;
    }
    err = alcp_drbg_randomize(
        &handle, &output[0], size_output, cSecurityStrength, NULL, 0);
    if (alcp_is_error(err)) {
        std::cout << "Error alcp_drbg_randomize" << std::endl;
        goto dealloc_exit;
    }
    err = alcp_drbg_randomize(
        &handle, &output[0], size_output, cSecurityStrength, NULL, 0);
    if (alcp_is_error(err)) {
        std::cout << "Error alcp_drbg_randomize" << std::endl;
        goto dealloc_exit;
    }

    alcp_drbg_finish(&handle);
    if (alcp_is_error(err)) {
        std::cout << "Error alcp_drbg_finish" << std::endl;
        return -1;
    }
    goto exit;

dealloc_exit:
    if (handle.ch_context) {
        free(handle.ch_context);
        handle.ch_context = nullptr;
    }
    return -1;

exit:
    if (handle.ch_context) {
        free(handle.ch_context);
        handle.ch_context = nullptr;
    }
    std::cout << "Passed for output size: " << size_output << " Entropy len "
              << size_max_entropy_len << " Nonce len " << size_max_nonce_len
              << std::endl;
    return 0;
}