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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/alcp.h"
#include <malloc.h>
#include <stdio.h>
#include <string.h>

static alc_mac_handle_t handle;

alc_error_t
poly1305_demo(Uint8*       data,
              Uint32       dataLen,
              Uint8*       mac,
              Uint32       mac_size,
              const Uint8* key,
              Uint64       key_size)
{

    alc_error_t err = ALC_ERROR_NONE;

    handle.ch_context = malloc(alcp_mac_context_size());

    if (handle.ch_context == NULL) {
        return ALC_ERROR_GENERIC;
    }

    err = alcp_mac_request(&handle, ALC_MAC_POLY1305);
    if (alcp_is_error(err)) {
        printf("Error Occurred on MAC Request - %lu\n", err);
        return err;
    }

    printf("Request Success!\n");

    err = alcp_mac_init(&handle, key, key_size, NULL);
    if (alcp_is_error(err)) {
        printf("Error Occurred on MAC Init - %lu\n", err);
        return err;
    }

    printf("Init Success!\n");

    // Update can be called multiple times with smaller chunks of the data
    err = alcp_mac_update(&handle, data, dataLen);
    if (alcp_is_error(err)) {
        printf("Error Occurred on MAC Update\n");
        return err;
    }
    printf("Mac Generation Success!\n");

    err = alcp_mac_finalize(&handle, mac, mac_size);
    if (alcp_is_error(err)) {
        printf("Error Occurred on MAC Finalize\n");
        return err;
    }

    printf("Mac Copy Success!\n");
    alcp_mac_finish(&handle);
    free(handle.ch_context);
    return err;
}

int
main(int argc, char const* argv[])
{
#if 0 // temporarily disabled reference kernel support to be added in next PR
    alc_error_t err;

    Uint8 key[32] = { 0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
                      0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
                      0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
                      0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b };

    Uint8 data[16] = { 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72,
                       0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f };

    Uint8 expectedMac[] = { 0xfd, 0x86, 0x1c, 0x71, 0x84, 0xf9, 0x8f, 0x45,
                            0xdc, 0x6d, 0x5b, 0x4d, 0xc6, 0xc0, 0x81, 0xe4 };

    Uint64 mac_size = 16;
    Uint8  mac[mac_size];
    err = poly1305_demo(data, sizeof(data), mac, mac_size, key, sizeof(key));
    if (alcp_is_error(err)) {
        printf("Error in CMAC\n");
        return -1;
    } else {
        if (memcmp(mac, expectedMac, mac_size) == 0) {
            printf("Poly1305 verified!\n");
        } else {
            printf("Poly1305 failure!\n");
        }
    }
#endif
    return 0;
}
