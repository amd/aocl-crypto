/*
 * Copyright (C) 2021-2024, Advanced Micro Devices. All rights reserved.
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
 * @brief Stores length of key
 *
 * @typedef enum   alc_key_len_t
 */
typedef enum alc_key_len
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

#endif /* _ALCP_KEY_H_ */
       /**
        * @}
        */
