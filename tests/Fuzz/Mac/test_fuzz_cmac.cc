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
ALCP_Fuzz_Cmac(const Uint8* buf, size_t len)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    size_t             size_input = stream.ConsumeIntegral<Uint16>();
    size_t             size_key   = stream.ConsumeIntegral<Uint16>();
    std::vector<Uint8> fuzz_key   = stream.ConsumeBytes<Uint8>(size_key);
    std::vector<Uint8> fuzz_input = stream.ConsumeBytes<Uint8>(size_input);

    Uint64 mac_size = 16;
    Uint8  mac[mac_size];

    std::cout << "Running for Input size: " << size_input << " and Key size "
              << size_key << std::endl;

    alc_mac_info_t   macinfo{};
    alc_mac_handle_t handle{};

    /* allocate context */
    handle.ch_context = malloc(alcp_mac_context_size());
    if (handle.ch_context == nullptr) {
        std::cout << "Error! Handle is null" << std::endl;
        return -1;
    }
    /* request */
    err = alcp_mac_request(&handle, ALC_MAC_CMAC);
    if (alcp_is_error(err)) {
        std::cout << "Error! alcp_mac_request" << std::endl;
        goto dealloc;
    }
    /* initialize */
    macinfo.cmac.ci_type = ALC_CIPHER_TYPE_AES;
    macinfo.cmac.ci_mode = ALC_AES_MODE_NONE;
    err = alcp_mac_init(&handle, &fuzz_key[0], size_key, &macinfo);
    if (alcp_is_error(err)) {
        std::cout << "Error! alcp_mac_init" << std::endl;
        goto dealloc;
    }
    /* mac update */
    err = alcp_mac_update(&handle, &fuzz_input[0], size_input);
    if (alcp_is_error(err)) {
        std::cout << "Error! alcp_mac_update" << std::endl;
        goto dealloc;
    }
    /* finalize */
    err = alcp_mac_finalize(&handle, mac, mac_size);
    if (alcp_is_error(err)) {
        std::cout << "Error! alcp_mac_finalize" << std::endl;
        goto dealloc;
    }
    goto out;

dealloc:
    alcp_mac_finish(&handle);
    free(handle.ch_context);
    return -1;

out:
    alcp_mac_finish(&handle);
    free(handle.ch_context);
    std::cout << "Test passed for Input size: " << size_input
              << " and Key size " << size_key << std::endl;
    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    int retval = 0;
    if (ALCP_Fuzz_Cmac(Data, Size) != 0) {
        std::cout << "CMAC fuzz test failed" << std::endl;
        return retval;
    }
    return retval;
}