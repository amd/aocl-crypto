/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "alcp/macros.h"
#include "alcp/types.h"

EXTERN_C_BEGIN

typedef enum _alc_error_generic
{
    /*
     * All is well
     */
    ALC_ERROR_NONE = 0UL,

    /*
     * An Error,
     *    but cant be categorized correctly
     */
    ALC_ERROR_GENERIC,

    /*
     * Not Supported,
     *  Any of Feature, configuration,  Algorithm or  Keysize not supported
     */
    ALC_ERROR_NOT_SUPPORTED,

    /*
     * Not Permitted,
     *  Operation supported but not permitted by this module/user etc.
     *  Kind of permission Denied situation, could be from the OS
     */
    ALC_ERROR_NOT_PERMITTED,

    /*
     * Exists,
     *  Something that is already exists is requested to register or replace
     */
    ALC_ERROR_EXISTS,

    /*
     * Does not Exist,
     *   Requested configuration/algorithm/module/feature  does not exists
     */
    ALC_ERROR_NOT_EXISTS,

    /*
     * Invalid argument
     */
    ALC_ERROR_INVALID_ARG,

    /*
     * Bad Internal State,
     *   Algorithm/context is in bad state due to internal Error
     */
    ALC_ERROR_BAD_STATE,

    /*
     * No Memory,
     *  Not enough free space available, Unable to allocate memory
     */
    ALC_ERROR_NO_MEMORY,

    /*
     * Data validation failure,
     *   Invalid pointer / Sent data is invalid
     */
    ALC_ERROR_INVALID_DATA,

    /*
     * Size Error,
     *   Data/Key size is invalid
     */
    ALC_ERROR_INVALID_SIZE,

    /*
     * Hardware Error,
     *   not in sane state, or failed during operation
     */
    ALC_ERROR_HARDWARE_FAILURE,

    /* There is not enough entropy for RNG
        retry needed with more entropy */
    ALC_ERROR_NO_ENTROPY,

    /*
     *The Tweak key and Encryption is same
     *for AES-XTS mode
     */
    ALC_ERROR_DUPLICATE_KEY,

} alc_error_generic_t;

typedef Uint64 alc_error_t;

/**
 * \brief        Converts AOCL Crypto errors to human readable form
 * \notes        This is internal usage only, prints Filename and line number
 *
 * \param err    Actual Error
 * \param buf    Buffer to write the Error message to
 * \param size   Size of the buffer @buf
 */

ALCP_API_EXPORT void
alcp_error_str(alc_error_t err, Uint8* buf, Uint64 size);

/**
 * \brief        Returns true if an error has occurred
 * \notes        This is the only way to check if an error has occurred in the
 *               previous call.
 *
 * \param err    Actual Error
 */
ALCP_API_EXPORT bool
alcp_is_error(alc_error_t err);

/**
 * \brief        Clears the error and releases any resources
 * \notes        At the end of using the error variable, alcp_error_clear()
 * must be called, memory leak would occur otherwise.
 *
 * \param err    Actual Error
 */
ALCP_API_EXPORT void
alcp_error_clear(alc_error_t err);

EXTERN_C_END

#endif /* _ALCP_ERROR_H_ */
