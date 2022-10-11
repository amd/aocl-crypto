/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
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
#include "alcp/digest.h"
#include "alcp/key.h"

typedef enum _alc_mac_type
{
    ALC_MAC_HMAC,
    ALC_MAC_CMAC
} alc_mac_type_t;

typedef struct _alc_hmac_info
{
    // Info about the hash function to be used in HMAC
    alc_digest_info_t hmac_digest;
    // Other specific info about HMAC

} alc_hmac_info_t, *alc_hmac_info_p;

typedef struct _alc_cmac_info
{
    alc_cipher_info_t cmac_cipher;
    // Other specific info about CMAC
} alc_cmac_info_t, *alc_cmac_info_p;

typedef struct _alc_mac_info_t
{
    alc_mac_type_t mi_type;
    union
    {
        alc_hmac_info_t hmac;
        alc_cmac_info_t cmac;
    } mi_algoinfo;

    // any other common fields that are needed
    alc_key_info_t mi_keyinfo;
} alc_mac_info_t, *alc_mac_info_p;
