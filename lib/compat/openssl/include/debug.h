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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "provider/config.h"
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _OPENSSL_DEBUG_H
#define _OPENSSL_DEBUG_H 2

#ifdef ALCP_COMPAT_ENABLE_DEBUG
#define DBG_PRINT(prfx, fmt, ...) printf(prfx##fmt, __VA_ARGS__)

#define ENTER()    printf("Enter : %s:%d\n", __func__, __LINE__);
#define HERE()     printf("Here : %s:%d\n", __func__, __LINE__)
#define EXIT()     printf("Exit : %s:%d\n", __func__, __LINE__)
#define PRINT(MSG) printf(MSG)

#else
#define ENTER()
#define HERE()
#define EXIT()
#define PRINT(MSG)

#endif

void
printHexString(const char* info, const unsigned char* bytes, int length);

#endif /* _OPENSSL_DEBUG_H */
