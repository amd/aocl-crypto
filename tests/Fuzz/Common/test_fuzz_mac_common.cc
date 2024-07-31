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

std::map<alc_digest_mode_t, alc_digest_len_t> mac_sha_mode_len_map = {
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

std::map<alc_digest_mode_t, std::string> mac_sha_mode_string_map = {
    { ALC_SHA2_224, "ALC_SHA2_224" },   { ALC_SHA2_256, "ALC_SHA2_256" },
    { ALC_SHA2_384, "ALC_SHA2_384" },   { ALC_SHA2_512, "ALC_SHA2_512" },
    { ALC_SHA3_224, "ALC_SHA3_224" },   { ALC_SHA3_256, "ALC_SHA3_256" },
    { ALC_SHA3_384, "ALC_SHA3_384" },   { ALC_SHA3_512, "ALC_SHA3_512" },
    { ALC_SHAKE_128, "ALC_SHAKE_128" }, { ALC_SHAKE_256, "ALC_SHAKE_256" }
};

std::map<_alc_mac_type, std::string> mac_type_string_map = {
    { ALC_MAC_HMAC, "HMAC" },
    { ALC_MAC_CMAC, "CMAC" },
    { ALC_MAC_POLY1305, "POLY1305" },
};

/**
 * @brief Life cycle testing
 Init->Init->Update->Init->Update->Finalize->Finalize->Init->Finalize
 */
bool
TestMacLifecycle_1(alc_mac_handle_t handle,
                   const Uint8*     fuzz_key,
                   Uint64           KeySize,
                   Uint8*           fuzz_input,
                   Uint64           InputSize,
                   Uint8*           mac,
                   Uint64           MacSize,
                   alc_mac_info_t   macinfo)
{
    if (alcp_is_error(alcp_mac_init(&handle, &fuzz_key[0], KeySize, &macinfo))
        || alcp_is_error(
            alcp_mac_init(&handle, &fuzz_key[0], KeySize, &macinfo))
        || alcp_is_error(alcp_mac_update(&handle, &fuzz_input[0], InputSize))
        || alcp_is_error(
            alcp_mac_init(&handle, &fuzz_key[0], KeySize, &macinfo))
        || alcp_is_error(alcp_mac_update(&handle, &fuzz_input[0], InputSize))
        || alcp_is_error(alcp_mac_finalize(&handle, mac, MacSize))
        || alcp_is_error(
            alcp_mac_init(&handle, &fuzz_key[0], KeySize, &macinfo))
        || alcp_is_error(alcp_mac_finalize(&handle, mac, MacSize))
        || alcp_is_error(alcp_mac_finalize(&handle, mac, MacSize))
        || alcp_is_error(alcp_mac_update(&handle, &fuzz_input[0], InputSize))) {
        std::cout << "MAC Neg lifecycle Test! "
                     "Init->Init->Update->Init->Update->Finalize->Finalize->"
                     "Init->Finalize->update"
                  << std::endl;
        return false;
    }
    return true;
}

/**
 * @brief Life cycle testing
  "Init->Update->Update->Finalize->Update->"
 */
bool
TestMacLifecycle_2(alc_mac_handle_t handle,
                   const Uint8*     fuzz_key,
                   Uint64           KeySize,
                   Uint8*           fuzz_input,
                   Uint64           InputSize,
                   Uint8*           mac,
                   Uint64           MacSize,
                   alc_mac_info_t   macinfo)
{
    if (alcp_is_error(alcp_mac_init(&handle, &fuzz_key[0], KeySize, &macinfo))
        || alcp_is_error(
            alcp_mac_init(&handle, &fuzz_key[0], KeySize, &macinfo))
        || alcp_is_error(alcp_mac_update(&handle, &fuzz_input[0], InputSize))
        || alcp_is_error(
            alcp_mac_init(&handle, &fuzz_key[0], KeySize, &macinfo))
        || alcp_is_error(alcp_mac_update(&handle, &fuzz_input[0], InputSize))
        || alcp_is_error(alcp_mac_finalize(&handle, mac, MacSize))
        || alcp_is_error(alcp_mac_update(&handle, &fuzz_input[0], InputSize))) {
        std::cout << "MAC Neg lifecycle Test! "
                     "Init->Update->Update->Finalize->Update->"
                  << std::endl;
        return false;
    }
    return true;
}

/* the second argument is relevant only for Hmac*/
int
ALCP_Fuzz_Mac(_alc_mac_type     mac_type,
              alc_digest_mode_t mode,
              const Uint8*      buf,
              size_t            len,
              bool              TestNegLifeCycle)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    size_t             size_key   = stream.ConsumeIntegral<Uint16>();
    std::vector<Uint8> fuzz_key   = stream.ConsumeBytes<Uint8>(size_key);
    size_t             size_input = stream.ConsumeIntegral<Uint16>();
    std::vector<Uint8> fuzz_input = stream.ConsumeBytes<Uint8>(size_input);

    static std::uniform_int_distribution<int> id(1, 50);
    int                                       mac_update_call_cout = id(rng);

    /* for HMAC its sha size, for CMAC and Poly1305, its 16 */
    Uint64 mac_size = 16;
    if (mac_type == ALC_MAC_HMAC) {
        mac_size = mac_sha_mode_len_map[mode] / 8;
    }
    Uint8 mac[mac_size];

    std::cout << mac_type_string_map[mac_type]
              << " Running for Input size: " << size_input
              << " and Key size: " << size_key << " Mac size: " << mac_size
              << std::endl;

    alc_mac_info_t macinfo = { { mode } };

    alc_mac_handle_t handle{};

    /* allocate context */
    handle.ch_context = malloc(alcp_mac_context_size());
    if (handle.ch_context == nullptr) {
        std::cout << "Error! Handle is null" << std::endl;
        return -1;
    }
    /* request */
    err = alcp_mac_request(&handle, mac_type);
    if (alcp_is_error(err)) {
        std::cout << "Error! alcp_mac_request" << std::endl;
        goto dealloc;
    }

    /* only for cmac */
    if (mac_type == ALC_MAC_CMAC) {
        macinfo.cmac.ci_mode = ALC_AES_MODE_NONE;
    }

    /* lifecycle tests*/
    if (TestNegLifeCycle) {
        if (!TestMacLifecycle_1(handle,
                                &fuzz_key[0],
                                fuzz_key.size(),
                                &fuzz_input[0],
                                fuzz_input.size(),
                                mac,
                                mac_size,
                                macinfo)) {
            goto dealloc;
        }
        if (!TestMacLifecycle_2(handle,
                                &fuzz_key[0],
                                fuzz_key.size(),
                                &fuzz_input[0],
                                fuzz_input.size(),
                                mac,
                                mac_size,
                                macinfo)) {
            goto dealloc;
        }
    } else {
        /* Positive lifecycle fuzz tests */
        /* Note: For POLY1305, the macinfo is ignored, it can be NULL */
        err = alcp_mac_init(&handle, &fuzz_key[0], fuzz_key.size(), &macinfo);
        if (alcp_is_error(err)) {
            std::cout << "Error! alcp_mac_init" << std::endl;
            goto dealloc;
        }
        /* mac update */
        for (int i = 0; i < mac_update_call_cout; i++) {
            err = alcp_mac_update(&handle, &fuzz_input[0], fuzz_input.size());
            if (alcp_is_error(err)) {
                std::cout << "Error! alcp_mac_update" << std::endl;
                goto dealloc;
            }
            std::cout << "Called macupdate for iteration:" << i << std::endl;
        }
        /* finalize */
        err = alcp_mac_finalize(&handle, mac, mac_size);
        if (alcp_is_error(err)) {
            std::cout << "Error! alcp_mac_finalize" << std::endl;
            goto dealloc;
        }
    }
    goto out;

dealloc:
    alcp_mac_finish(&handle);
    free(handle.ch_context);
    return -1;

out:
    alcp_mac_finish(&handle);
    free(handle.ch_context);
    std::cout << mac_type_string_map[mac_type]
              << " Test Passed for Input size: " << size_input
              << " and Key size: " << size_key << " Mac size: " << mac_size
              << std::endl;
    return 0;
}