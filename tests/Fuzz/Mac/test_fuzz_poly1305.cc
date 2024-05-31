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
ALCP_Fuzz_Poly1305(const Uint8* buf, size_t len)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    size_t             size       = stream.ConsumeIntegral<Uint16>();
    std::vector<Uint8> fuzz_key   = stream.ConsumeBytes<Uint8>(size);
    std::vector<Uint8> fuzz_input = stream.ConsumeBytes<Uint8>(size);

    const Uint8* key        = fuzz_key.data();
    Uint32       keySize    = fuzz_key.size();
    const Uint8* input      = fuzz_input.data();
    Uint32       input_size = fuzz_input.size();

    std::cout << "Running for Input size: " << input_size << " and Key size "
              << keySize << std::endl;

    Uint64 mac_size = 16;
    Uint8  mac[mac_size];

    const alc_key_info_t kinfo = { .algo = ALC_KEY_ALG_MAC,
                                   .len  = keySize * 8,
                                   .key  = key };

    alc_mac_info_t macinfo = { .mi_type    = ALC_MAC_POLY1305,
                               .mi_keyinfo = kinfo };

    alc_mac_handle_t handle;
    handle.ch_context = malloc(alcp_mac_context_size());
    if (handle.ch_context == NULL) {
        return ALC_ERROR_GENERIC;
    }
    err = alcp_mac_request(&handle, &macinfo);
    if (alcp_is_error(err)) {
        printf("Error Occurred on MAC Request - %lu\n", err);
        return -1;
    }
    err = alcp_mac_update(&handle, input, input_size);
    if (alcp_is_error(err)) {
        printf("Error Occurred on MAC Update\n");
        return -1;
    }
    err = alcp_mac_finalize(&handle, mac, mac_size);
    if (alcp_is_error(err)) {
        printf("Error Occurred on MAC Finalize\n");
        return -1;
    }
    alcp_mac_finish(&handle);
    free(handle.ch_context);

    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    int retval = 0;
    if (ALCP_Fuzz_Poly1305(Data, Size) != 0) {
        std::cout << "Poly1305 fuzz test failed" << std::endl;
        return retval;
    }
    return retval;
}