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
#ifndef _ALCP_ERROR_H_
#define _ALCP_ERROR_H_ 2

#include <assert.h>
#include <stdint.h>

#define ALC_ERROR_NONE             0UL
#define ALC_ERROR_GENERIC          1UL
#define ALC_ERROR_NOT_SUPPORTED    2UL
#define ALC_ERROR_NOT_PERMITTED    3UL
#define ALC_ERROR_EXISTS           4UL
#define ALC_ERROR_NOT_EXISTS       5UL
#define ALC_ERROR_NOT_PERMITTED    6UL
#define ALC_ERROR_INVALID_ARG      7UL
#define ALC_ERROR_BAD_STATE        8UL
#define ALC_ERROR_NO_MEMORY        9UL
#define ALC_ERROR_INVALID_DATA     10UL
#define ALC_ERROR_INVALID_SIZE     12UL
#define ALC_ERROR_HARDWARE_FAILURE 13UL

typedef void* alc_error_t;

/**
 * \brief        Converts AOCL Crypto errors to human readable form
 * \notes        This is internal usage only, prints Filename and line number
 *
 * \param err    Actual Error
 * \param buf    Buffer to write the Error message to
 * \param size   Size of the buffer @buf
 */

void
alcp_error_str(alc_error_t err, uint8_t* buf, uint64_t size);

bool
alcp_is_error(alc_error_t* err);

#endif /* _ALCP_ERROR_H_ */
