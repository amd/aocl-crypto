
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

std::map<alc_digest_mode_t, alc_digest_len_t> sha_mode_len_map = {
    { ALC_SHA2_224, ALC_DIGEST_LEN_224 },
    { ALC_SHA2_256, ALC_DIGEST_LEN_256 },
    { ALC_SHA2_384, ALC_DIGEST_LEN_384 },
    { ALC_SHA2_512, ALC_DIGEST_LEN_512 },
    { ALC_SHA3_224, ALC_DIGEST_LEN_224 },
    { ALC_SHA3_256, ALC_DIGEST_LEN_256 },
    { ALC_SHA3_384, ALC_DIGEST_LEN_384 },
    { ALC_SHA3_512, ALC_DIGEST_LEN_512 },
    { ALC_SHAKE_128, ALC_DIGEST_LEN_CUSTOM_SHAKE_128 },
    { ALC_SHAKE_256, ALC_DIGEST_LEN_CUSTOM_SHAKE_256 }
};

std::map<alc_digest_mode_t, std::string> sha_mode_string_map = {
    { ALC_SHA2_224, "ALC_SHA2_224" },   { ALC_SHA2_256, "ALC_SHA2_256" },
    { ALC_SHA2_384, "ALC_SHA2_384" },   { ALC_SHA2_512, "ALC_SHA2_512" },
    { ALC_SHA3_224, "ALC_SHA3_224" },   { ALC_SHA3_256, "ALC_SHA3_256" },
    { ALC_SHA3_384, "ALC_SHA3_384" },   { ALC_SHA3_512, "ALC_SHA3_512" },
    { ALC_SHAKE_128, "ALC_SHAKE_128" }, { ALC_SHAKE_256, "ALC_SHAKE_256" }
};

/**
 * @brief Life cycle testing init -> update -> finalize -> update -> init ->
 * update -> finalize -> init
 *
 */
bool
TestDigestLifecycle_1(alc_digest_handle_p handle,
                      const Uint8*        fuzz_input,
                      Uint64              InputSize,
                      Uint8*              output1,
                      Uint64              out_size)
{
    if (alcp_is_error(alcp_digest_init(handle))
        || (alcp_is_error(alcp_digest_init(handle)))
        || (alcp_is_error(
            alcp_digest_update(handle, &fuzz_input[0], InputSize)))
        || (alcp_is_error(alcp_digest_finalize(handle, output1, out_size)))
        || (alcp_is_error(alcp_digest_update(handle, &fuzz_input[0], InputSize))
            || alcp_is_error(alcp_digest_init(handle)))
        || alcp_is_error(alcp_digest_update(handle, &fuzz_input[0], InputSize))
        || alcp_is_error(alcp_digest_finalize(handle, output1, out_size))
        || alcp_is_error(alcp_digest_init(handle))) {
        std::cout << "Neg lifecycle Test FAIL! "
                     "Init->Init->Update->Finalize->Update->Init->update->"
                     "Finalize->Init"
                  << std::endl;
        return false;
    }
    return true;
}

/**
 * @brief Life cycle testing init -> init -> Finalize -> update
 */
bool
TestDigestLifecycle_2(alc_digest_handle_p handle,
                      const Uint8*        fuzz_input,
                      Uint64              InputSize,
                      Uint8*              output1,
                      Uint64              out_size)
{
    if (alcp_is_error(alcp_digest_init(handle))
        || (alcp_is_error(alcp_digest_init(handle)))
        || (alcp_is_error(alcp_digest_finalize(handle, output1, out_size)))
        || (alcp_is_error(
            alcp_digest_update(handle, &fuzz_input[0], InputSize)))) {
        std::cout << "Neg lifecycle Test FAIL! "
                     "Init->Init->Update->Finalize->Update->Init->update->"
                     "Finalize->Init"
                  << std::endl;
        return false;
    }
    return true;
}

/**
 * @brief Life cycle testing init -> finalize -> update -> ctx copy -> squeeze
 * -> update
 */
bool
TestDigestLifecycle_ctx_copy(alc_digest_handle_p handle,
                             alc_digest_handle_p handle_dup,
                             const Uint8*        fuzz_input,
                             Uint64              InputSize,
                             Uint8*              output1,
                             Uint8*              output2,
                             Uint64              out_size)
{
    /* invalid call, finalize on initialized dup handle, and trying to squeeze
     * output , then try to call update from the dup handle */
    if (alcp_is_error(
            alcp_digest_init(handle)
            || alcp_is_error(alcp_digest_finalize(handle, output1, out_size))
            || (alcp_is_error(
                alcp_digest_update(handle_dup, &fuzz_input[0], InputSize)))
            || alcp_is_error(alcp_digest_context_copy(handle, handle_dup))
            || alcp_is_error(
                alcp_digest_shake_squeeze(handle_dup, output2, out_size)))
        || alcp_is_error(
            alcp_digest_update(handle_dup, &fuzz_input[0], InputSize))) {
        std::cout << "Neg lifecycle Test FAIL! "
                     "Init->Finalize->Update->CtxCopy->Squeeze->Update"
                  << std::endl;
        return false;
    }
    return true;
}

/**
 * @brief Function to perform fuzz / lifecycle testing for specific digest mode
 **/
int
ALCP_Fuzz_Digest(alc_digest_mode_t mode,
                 const Uint8*      buf,
                 size_t            len,
                 bool              TestNegLifeCycle)
{
    FuzzedDataProvider stream(buf, len);

    size_t             size_input = stream.ConsumeIntegral<Uint16>();
    std::vector<Uint8> fuzz_input = stream.ConsumeBytes<Uint8>(size_input);

    size_t size_output_shake = stream.ConsumeIntegral<Uint16>();

    /* Initializing digest info */
    alc_error_t         err = ALC_ERROR_NONE;
    alc_digest_handle_p handle{}, handle_dup{};
    handle = new alc_digest_handle_t;

    Uint32 out_size = sha_mode_len_map[mode];

    int digest_update_call_cout;

    static std::uniform_int_distribution<int> id(1, 50);
    digest_update_call_cout = id(rng);

    /* for non-shake variants */
    if (out_size % 8 == 0) {
        out_size = out_size / 8;
    }
    /* for shake variants */
    else if (out_size == ALC_DIGEST_LEN_CUSTOM_SHAKE_128
             || out_size == ALC_DIGEST_LEN_CUSTOM_SHAKE_256) {
        out_size = size_output_shake;
        std::cout << "Requesting for Digest of size " << out_size << std::endl;
    } else {
        std::cout << sha_mode_len_map[mode] << " is not supported. Exiting.."
                  << std::endl;
        return -1;
    }

    std::cout << "Running Digest Fuzz test for SHA mode "
              << sha_mode_string_map[mode] << std::endl;

    /* output2 is to store digest data from duplicate handle */
    Uint8 output1[out_size], output2[out_size];

    /* allocate context */
    Uint64 context_size = alcp_digest_context_size();
    handle->context     = malloc(context_size);
    if (handle->context == nullptr) {
        std::cout << "Error: Mem alloc for digest context" << std::endl;
        return -1;
    }
    if (sha_mode_string_map[mode].find("SHAKE") != std::string::npos) {
        handle_dup          = new alc_digest_handle_t;
        handle_dup->context = malloc(context_size);
        if (handle_dup->context == nullptr) {
            std::cout << "Error: Mem alloc for digest dup context" << std::endl;
            return -1;
        }
    }

    std::cout << "Running for Input size:" << size_input << std::endl;
    err = alcp_digest_request(mode, handle);
    if (alcp_is_error(err)) {
        std::cout << "Error! alcp_digest_request for main handle" << std::endl;
        goto dealloc_exit;
    }

    if (TestNegLifeCycle) {
        if (!TestDigestLifecycle_1(
                handle, &fuzz_input[0], fuzz_input.size(), output1, out_size))
            goto dealloc_exit;
        if (!TestDigestLifecycle_2(
                handle, &fuzz_input[0], fuzz_input.size(), output1, out_size))
            goto dealloc_exit;

        /* for shake variants */
        if (sha_mode_string_map[mode].find("SHAKE") != std::string::npos)
            if (!TestDigestLifecycle_ctx_copy(handle,
                                              handle_dup,
                                              &fuzz_input[0],
                                              fuzz_input.size(),
                                              output1,
                                              output2,
                                              out_size))
                goto dealloc_exit;
    } else {
        err = alcp_digest_init(handle);
        if (alcp_is_error(err)) {
            std::cout << "Error! alcp_digest_init" << std::endl;
            goto dealloc_exit;
        }
        /* context copy */
        err = alcp_digest_context_copy(handle, handle_dup);
        if (alcp_is_error(err)) {
            std::cout << "Error! alcp_digest_context_copy" << std::endl;
            goto dealloc_exit;
        }
        /* call this multiple times in the positive lifecycle tests */
        for (int i = 0; i < digest_update_call_cout; i++) {
            std::cout << "Running digest update for loop:" << i << std::endl;
            err = alcp_digest_update(handle, &fuzz_input[0], fuzz_input.size());
            if (alcp_is_error(err)) {
                std::cout << "Error! alcp_digest_update" << std::endl;
                goto dealloc_exit;
            }
        }

        /* for shake variants */
        if (sha_mode_string_map[mode].find("SHAKE") != std::string::npos) {
            /* context copy */
            err = alcp_digest_context_copy(handle, handle_dup);
            if (alcp_is_error(err)) {
                std::cout << "Error! alcp_digest_context_copy" << std::endl;
                goto dealloc_exit;
            }
            err = alcp_digest_shake_squeeze(handle_dup, output2, out_size);
            if (alcp_is_error(err)) {
                std::cout << "Error! alcp_digest_shake_squeeze" << std::endl;
                goto dealloc_exit;
            }
        }
        err = alcp_digest_finalize(handle, output1, out_size);
        if (alcp_is_error(err)) {
            std::cout << "Error! alcp_digest_finalize" << std::endl;
            goto dealloc_exit;
        }
    }
    goto exit;

dealloc_exit:
    alcp_digest_finish(handle);
    if (handle->context != nullptr) {
        free(handle->context);
    }
    delete handle;
    /* FIXME, what if this was called on an uinitialized handle */
    if (sha_mode_string_map[mode].find("SHAKE") != std::string::npos) {
        alcp_digest_finish(handle_dup);
        if (handle_dup->context != nullptr) {
            free(handle_dup->context);
        }
        delete handle_dup;
    }
    return -1;

exit:
    alcp_digest_finish(handle);
    if (handle->context != nullptr) {
        free(handle->context);
    }
    delete handle;
    /* FIXME, what if this was called on an uinitialized handle */
    if (sha_mode_string_map[mode].find("SHAKE") != std::string::npos) {
        alcp_digest_finish(handle_dup);
        if (handle_dup->context != nullptr) {
            free(handle_dup->context);
        }
        delete handle_dup;
    }
    std::cout << "Passed " << sha_mode_len_map[mode]
              << " for Input size:" << size_input << std::endl;
    return 0;
}