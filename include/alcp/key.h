/*
 * Copyright (C) 2021-2023, Advanced Micro Devices. All rights reserved.
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

#ifndef _ALCP_KEY_H_
#define _ALCP_KEY_H_ 2

#include "alcp/types.h"
#include <stdint.h>

/**
 * @addtogroup cipher
 *
 * @{
 */

/**
 * @brief Stores Type of Key being used for Cipher
 *
 * @typedef enum alc_key_type_t
 */
typedef enum
{
    ALC_KEY_TYPE_UNKNOWN = 0,

    ALC_KEY_TYPE_SYMMETRIC = 0x10, /* Will cover all AES,DES,CHACHA20 etc */
    ALC_KEY_TYPE_PRIVATE   = 0x20,
    ALC_KEY_TYPE_PUBLIC    = 0x40,
    ALC_KEY_TYPE_DER       = 0x80,
    ALC_KEY_TYPE_PEM       = 0x100,
    ALC_KEY_TYPE_CUSTOM    = 0x200,

    ALC_KEY_TYPE_MAX,
} alc_key_type_t;

/**
 * @brief Stores Algorithm for key
 *
 * @typedef enum   alc_key_alg_t
 */
typedef enum
{
    ALC_KEY_ALG_WILDCARD,
    ALC_KEY_ALG_DERIVATION,
    ALC_KEY_ALG_AGREEMENT,
    ALC_KEY_ALG_SYMMETRIC,
    ALC_KEY_ALG_SIGN,
    ALC_KEY_ALG_AEAD,
    ALC_KEY_ALG_MAC,
    ALC_KEY_ALG_HASH,

    ALC_KEY_ALG_MAX,
} alc_key_alg_t;

/**
 * @brief Stores length of key
 *
 * @typedef enum   alc_key_len_t
 */
typedef enum
{
    ALC_KEY_LEN_128 = 128,
    ALC_KEY_LEN_192 = 192,
    ALC_KEY_LEN_256 = 256,
    ALC_KEY_LEN_384 = 384,
    ALC_KEY_LEN_512 = 512,

    ALC_KEY_LEN_1024 = 1024,
    ALC_KEY_LEN_2048 = 2048,
    ALC_KEY_LEN_4096 = 4096,

    ALC_KEY_LEN_CUSTOM,
    ALC_KEY_LEN_DEFAULT = ALC_KEY_LEN_128,
} alc_key_len_t;

/**
 * @brief Stores Format of key
 *
 * @typedef enum   alc_key_fmt_t
 */
typedef enum
{
    ALC_KEY_FMT_RAW,    /* Default should be fine */
    ALC_KEY_FMT_BASE64, /* Base64 encoding */
} alc_key_fmt_t;

/**
 * @brief Store info related to key.
 *
 * @struct alc_key_info_t
 */
typedef struct _alc_key_info
{
    alc_key_type_t type;
    alc_key_fmt_t  fmt;
    alc_key_alg_t  algo;
    alc_key_len_t  len_type;
    Uint32         len; /* Key length in bits */
    const Uint8*   key; /* Key follows the rest of the structure */

} alc_key_info_t, *alc_key_info_p;

// FIXME: All functions below are not backed by any function definition, needs
// to be removed
/**
 * @brief    Allows caller to get Algorithm used in key
 * @note    currently not in use.
 * @param [in]   kinfo Stores info regarding key
 *
 * @return  alc_key_alg_t Enum which stores algorithm used for key
 */
alc_key_alg_t
alcp_key_get_algo(alc_key_info_t* kinfo);

/**
 * @brief    Allows caller to get Algorithm used in key
 * @note    currently not in use.
 * @param [in]   kinfo Stores info regarding key
 *
 * @return  alc_key_type_t Enum which stores type of key used
 */
alc_key_type_t
alcp_key_get_type(alc_key_info_t* kinfo);

#endif /* _ALCP_KEY_H_ */
       /**
        * @}
        */
